// Command hf4-archive-collect builds one signed HF4 supply archive from a
// DERO node's JSON-RPC. It is a reference collector, not an audited tool.
//
// The collector writes canonical blocks.jsonl and bodies.jsonl catalogs, the
// content-addressed body files, and a signed manifest. Run it once per
// operator; verification requires two archives with distinct sources, operators,
// and signing keys.
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/transaction"
)

type Manifest struct {
	SchemaVersion     uint64 `json:"schema_version"`
	Network           string `json:"network"`
	ArchiveID         string `json:"archive_id"`
	SourceID          string `json:"source_id"`
	OperatorID        string `json:"operator_id"`
	CollectionCommand string `json:"collection_command"`
	Endpoint          string `json:"endpoint"`
	SourceCommit      string `json:"source_commit"`
	FirstTopoHeight   uint64 `json:"first_topo_height"`
	ThroughTopoHeight uint64 `json:"through_topo_height"`
	GenesisBlockID    string `json:"genesis_block_id,omitempty"`
	StartBlockID      string `json:"start_block_id,omitempty"`
	StartStateRoot    string `json:"start_state_root,omitempty"`
	AnchorBlockID     string `json:"anchor_block_id"`
	AnchorStateRoot   string `json:"anchor_state_root"`
	BlocksSHA256      string `json:"blocks_sha256"`
	BodiesSHA256      string `json:"bodies_sha256"`
}

type blockRow struct {
	TopoHeight        uint64   `json:"topo_height"`
	BlockHash         string   `json:"block_hash"`
	TransactionHashes []string `json:"transaction_hashes"`
}

type bodyRow struct {
	TopoHeight       uint64 `json:"topo_height"`
	TransactionIndex uint64 `json:"transaction_index"`
	TransactionHash  string `json:"transaction_hash"`
	BodySHA256       string `json:"body_sha256"`
	BodySize         uint64 `json:"body_size"`
}

type rpcBlock struct {
	Blob        string `json:"blob"`
	MerkleHash  string `json:"merkle_hash"`
	BlockHeader struct {
		Hash       string `json:"hash"`
		Height     uint64 `json:"height"`
		TopoHeight uint64 `json:"topoheight"`
	} `json:"block_header"`
}

type rpcTransactions struct {
	TxsAsHex []string `json:"txs_as_hex"`
}

var httpClient = &http.Client{
	Timeout:   45 * time.Second,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
}

func rpc(endpoint, method string, params interface{}, out interface{}) error {
	payload := map[string]interface{}{"jsonrpc": "2.0", "id": "1", "method": method}
	if params != nil {
		payload["params"] = params
	}
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	response, err := httpClient.Post(endpoint, "application/json", bytes.NewReader(requestBody))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return err
	}
	if envelope.Error != nil {
		return fmt.Errorf("rpc %s: %s", method, envelope.Error.Message)
	}
	return json.Unmarshal(envelope.Result, out)
}

func fetchBlock(endpoint string, height uint64) (*rpcBlock, error) {
	var result rpcBlock
	if err := rpc(endpoint, "getblock", map[string]uint64{"height": height}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func fetchBodies(endpoint string, txHashes []string) ([][]byte, error) {
	var result rpcTransactions
	if err := rpc(endpoint, "gettransactions", map[string][]string{"txs_hashes": txHashes}, &result); err != nil {
		return nil, err
	}
	if len(result.TxsAsHex) != len(txHashes) {
		return nil, fmt.Errorf("rpc returned %d bodies for %d transactions", len(result.TxsAsHex), len(txHashes))
	}
	bodies := make([][]byte, len(txHashes))
	for index, bodyHex := range result.TxsAsHex {
		if bodyHex == "" {
			return nil, fmt.Errorf("missing body for transaction %s", txHashes[index])
		}
		body, err := hex.DecodeString(bodyHex)
		if err != nil {
			return nil, fmt.Errorf("decode transaction %s body: %w", txHashes[index], err)
		}
		bodies[index] = body
	}
	return bodies, nil
}

func isLowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == length/2
}

func requireFlag(name, value string) string {
	if strings.TrimSpace(value) == "" {
		fmt.Fprintf(os.Stderr, "%s is required\n", name)
		os.Exit(2)
	}
	return value
}

func loadSigningKey(path string) (ed25519.PrivateKey, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	seedText := strings.TrimSpace(string(data))
	if !isLowerHex(seedText, 64) {
		return nil, "", fmt.Errorf("%s must contain one 32-byte lowercase hex Ed25519 seed", path)
	}
	seed, _ := hex.DecodeString(seedText)
	key := ed25519.NewKeyFromSeed(seed)
	return key, hex.EncodeToString(key.Public().(ed25519.PublicKey)), nil
}

func main() {
	rpcURL := flag.String("rpc", "", "DERO daemon JSON-RPC endpoint")
	network := flag.String("network", "mainnet", "expected network label")
	from := flag.Uint64("from", 0, "first topo height (0 for genesis)")
	to := flag.Uint64("to", 0, "anchor topo height")
	genesis := flag.String("genesis-block", "", "approved genesis block ID (from=0)")
	startBlock := flag.String("start-block", "", "approved section start block ID (from>0)")
	startState := flag.String("start-state-root", "", "approved section start state root (from>0)")
	outDir := flag.String("out", "", "output archive directory")
	archiveID := flag.String("archive-id", "", "unique archive ID")
	sourceID := flag.String("source-id", "", "approved source ID")
	operatorID := flag.String("operator-id", "", "approved operator ID")
	endpoint := flag.String("endpoint", "", "public archive endpoint or non-identifying label")
	command := flag.String("collection-command", "", "exact reproducible collection command")
	sourceCommit := flag.String("source-commit", "", "full lowercase 40- or 64-character source commit")
	keyFile := flag.String("key-file", "", "file containing one 32-byte lowercase hex Ed25519 seed")
	flag.Parse()

	requireFlag("-rpc", *rpcURL)
	requireFlag("-out", *outDir)
	requireFlag("-archive-id", *archiveID)
	requireFlag("-source-id", *sourceID)
	requireFlag("-operator-id", *operatorID)
	requireFlag("-endpoint", *endpoint)
	requireFlag("-collection-command", *command)
	requireFlag("-source-commit", *sourceCommit)
	requireFlag("-key-file", *keyFile)
	if *to < *from {
		fmt.Fprintln(os.Stderr, "-to must be greater than or equal to -from")
		os.Exit(2)
	}
	if !isLowerHex(*sourceCommit, 40) && !isLowerHex(*sourceCommit, 64) {
		fmt.Fprintln(os.Stderr, "-source-commit must be 40 or 64 lowercase hex characters")
		os.Exit(2)
	}
	if *from == 0 {
		if !isLowerHex(*genesis, 64) {
			fmt.Fprintln(os.Stderr, "-genesis-block must be one 64-character lowercase hex hash when -from is 0")
			os.Exit(2)
		}
		if *startBlock != "" || *startState != "" {
			fmt.Fprintln(os.Stderr, "-start-block and -start-state-root require -from greater than 0")
			os.Exit(2)
		}
	} else {
		if *genesis != "" {
			fmt.Fprintln(os.Stderr, "-genesis-block must be empty when -from is greater than 0")
			os.Exit(2)
		}
		if !isLowerHex(*startBlock, 64) || !isLowerHex(*startState, 64) {
			fmt.Fprintln(os.Stderr, "-start-block and -start-state-root must be 64-character lowercase hex hashes")
			os.Exit(2)
		}
	}

	signingKey, publicKey, err := loadSigningKey(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	blocksPath := filepath.Join(*outDir, "blocks.jsonl")
	bodiesPath := filepath.Join(*outDir, "bodies.jsonl")
	blocksFile, err := os.Create(blocksPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer blocksFile.Close()
	bodiesFile, err := os.Create(bodiesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer bodiesFile.Close()

	blocksHash := sha256.New()
	bodiesHash := sha256.New()
	blocksWriter := bufio.NewWriterSize(io.MultiWriter(blocksFile, blocksHash), 1<<20)
	bodiesWriter := bufio.NewWriterSize(io.MultiWriter(bodiesFile, bodiesHash), 1<<20)
	defer blocksWriter.Flush()
	defer bodiesWriter.Flush()

	expectedTopo := *from
	firstBlockID := ""
	lastBlockID := ""
	lastStateRoot := ""
	startStateSeen := ""
	transactionCount := uint64(0)
	for height := *from; height <= *to; height++ {
		source, err := fetchBlock(*rpcURL, height)
		if err != nil {
			fmt.Fprintf(os.Stderr, "block %d: %v\n", height, err)
			os.Exit(1)
		}
		blockBytes, err := hex.DecodeString(source.Blob)
		if err != nil {
			fmt.Fprintf(os.Stderr, "block %d blob: %v\n", height, err)
			os.Exit(1)
		}
		var decoded block.Block
		if err := decoded.Deserialize(blockBytes); err != nil {
			fmt.Fprintf(os.Stderr, "block %d deserialize: %v\n", height, err)
			os.Exit(1)
		}
		blockID := decoded.GetHash().String()
		if source.BlockHeader.Hash != "" && !strings.EqualFold(source.BlockHeader.Hash, blockID) {
			fmt.Fprintf(os.Stderr, "block %d hash mismatch: rpc %s, decoded %s\n", height, source.BlockHeader.Hash, blockID)
			os.Exit(1)
		}
		topo := source.BlockHeader.TopoHeight
		if topo == 0 {
			topo = height
		}
		if topo != expectedTopo {
			fmt.Fprintf(os.Stderr, "block %d topo %d out of order; want %d\n", height, topo, expectedTopo)
			os.Exit(1)
		}
		if height == *from {
			firstBlockID = blockID
			startStateSeen = source.MerkleHash
			if *from == 0 && blockID != *genesis {
				fmt.Fprintf(os.Stderr, "genesis block %s does not match approved %s\n", blockID, *genesis)
				os.Exit(1)
			}
			if *from > 0 {
				if blockID != *startBlock {
					fmt.Fprintf(os.Stderr, "start block %s does not match approved %s\n", blockID, *startBlock)
					os.Exit(1)
				}
				if source.MerkleHash == "" || !strings.EqualFold(source.MerkleHash, *startState) {
					fmt.Fprintf(os.Stderr, "start state root %s does not match approved %s\n", source.MerkleHash, *startState)
					os.Exit(1)
				}
			}
		}
		lastBlockID = blockID
		lastStateRoot = source.MerkleHash

		txHashes := make([]string, len(decoded.Tx_hashes))
		for index, txID := range decoded.Tx_hashes {
			txHashes[index] = txID.String()
		}
		bodies := make([][]byte, len(txHashes))
		if len(txHashes) > 0 {
			bodies, err = fetchBodies(*rpcURL, txHashes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "block %d bodies: %v\n", height, err)
				os.Exit(1)
			}
		}
		for index, txID := range decoded.Tx_hashes {
			body := bodies[index]
			var decodedTx transaction.Transaction
			if err := decodedTx.Deserialize(body); err != nil {
				fmt.Fprintf(os.Stderr, "transaction %s deserialize: %v\n", txHashes[index], err)
				os.Exit(1)
			}
			if decodedTx.GetHash() != txID {
				fmt.Fprintf(os.Stderr, "transaction %s body hash mismatch\n", txHashes[index])
				os.Exit(1)
			}
			digest := sha256.Sum256(body)
			digestHex := hex.EncodeToString(digest[:])
			bodyPath := filepath.Join(*outDir, "tx", txHashes[index], digestHex+".hex")
			if err := os.MkdirAll(filepath.Dir(bodyPath), 0o755); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := os.WriteFile(bodyPath, []byte(hex.EncodeToString(body)+"\n"), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			row, err := json.Marshal(bodyRow{
				TopoHeight: topo, TransactionIndex: uint64(index), TransactionHash: txHashes[index],
				BodySHA256: digestHex, BodySize: uint64(len(body)),
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			bodiesWriter.Write(row)
			bodiesWriter.WriteByte('\n')
			transactionCount++
		}

		row, err := json.Marshal(blockRow{TopoHeight: topo, BlockHash: blockID, TransactionHashes: txHashes})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		blocksWriter.Write(row)
		blocksWriter.WriteByte('\n')
		expectedTopo++
		if (height-*from+1)%100 == 0 {
			fmt.Fprintf(os.Stderr, "collected %d/%d blocks, %d transactions\n", height-*from+1, *to-*from+1, transactionCount)
		}
	}
	if err := blocksWriter.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := bodiesWriter.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if lastBlockID == "" {
		fmt.Fprintln(os.Stderr, "no blocks collected")
		os.Exit(1)
	}
	if lastStateRoot == "" {
		fmt.Fprintln(os.Stderr, "anchor state root is empty; the node must report merkle_hash")
		os.Exit(1)
	}

	manifest := Manifest{
		SchemaVersion: 1, Network: *network, ArchiveID: *archiveID, SourceID: *sourceID,
		OperatorID: *operatorID, CollectionCommand: *command, Endpoint: *endpoint,
		SourceCommit: *sourceCommit, FirstTopoHeight: *from, ThroughTopoHeight: *to,
		AnchorBlockID: lastBlockID, AnchorStateRoot: lastStateRoot,
		BlocksSHA256: hex.EncodeToString(blocksHash.Sum(nil)), BodiesSHA256: hex.EncodeToString(bodiesHash.Sum(nil)),
	}
	if *from == 0 {
		manifest.GenesisBlockID = firstBlockID
	} else {
		manifest.StartBlockID = firstBlockID
		manifest.StartStateRoot = startStateSeen
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	manifestPath := filepath.Join(*outDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	signature := ed25519.Sign(signingKey, manifestBytes)
	if err := os.WriteFile(filepath.Join(*outDir, "manifest.sig"), []byte(hex.EncodeToString(signature)+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("archive=%s blocks=%d transactions=%d first=%s anchor=%s\n", *archiveID, *to-*from+1, transactionCount, firstBlockID, lastBlockID)
	fmt.Printf("anchor_state_root=%s\n", lastStateRoot)
	fmt.Printf("signing_public_key=%s\n", publicKey)
	fmt.Printf("manifest=%s\n", manifestPath)
}
