// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chzyer/readline"
	"github.com/deroproject/derohe/astrobwt/astrobwt_fast"
	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/docopt/docopt-go"
	"github.com/go-logr/logr"
	"github.com/gorilla/websocket"
)

//import "github.com/deroproject/derohe/cryptography/crypto"

var mutex sync.RWMutex
var job rpc.GetBlockTemplate_Result
var job_counter int64
var maxdelay int = 10000
var threads int
var iterations int = 100
var max_pow_size int = 819200 //astrobwt.MAX_LENGTH
var wallet_address string
var daemon_rpc_address string

var counter uint64
var hash_rate uint64
var Difficulty uint64
var our_height int64

var block_counter uint64
var mini_block_counter uint64
var rejected uint64
var logger logr.Logger

var command_line string = `dero-miner
DERO CPU Miner for AstroBWT.
ONE CPU, ONE VOTE.
http://wiki.dero.io

Usage:
  dero-miner  --wallet-address=<wallet_address> [--daemon-rpc-address=<minernode1.dero.live:10100>] [--mining-threads=<threads>] [--testnet] [--debug]
  dero-miner --bench 
  dero-miner -h | --help
  dero-miner --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --bench  	    Run benchmark mode.
  --daemon-rpc-address=<127.0.0.1:10102>    Miner will connect to daemon RPC on this port (default minernode1.dero.live:10100).
  --wallet-address=<wallet_address>    This address is rewarded when a block is mined sucessfully.
  --mining-threads=<threads>         Number of CPU threads for mining [default: ` + fmt.Sprintf("%d", runtime.GOMAXPROCS(0)) + `]

Example Mainnet: ./dero-miner-linux-amd64 --wallet-address dero1qy0ehnqjpr0wxqnknyc66du2fsxyktppkr8m8e6jvplp954klfjz2qqhmy4zf --daemon-rpc-address=minernode1.dero.live:10100
Example Testnet: ./dero-miner-linux-amd64 --wallet-address deto1qy0ehnqjpr0wxqnknyc66du2fsxyktppkr8m8e6jvplp954klfjz2qqdzcd8p --daemon-rpc-address=127.0.0.1:40402 
If daemon running on local machine no requirement of '--daemon-rpc-address' argument. 
`
var Exit_In_Progress = make(chan bool)

func main() {

	var err error

	globals.Arguments, err = docopt.Parse(command_line, nil, true, config.Version.String(), false)

	if err != nil {
		fmt.Printf("Error while parsing options err: %s\n", err)
		return
	}

	// We need to initialize readline first, so it changes stderr to ansi processor on windows

	l, err := readline.NewEx(&readline.Config{
		//Prompt:          "\033[92mDERO:\033[32m»\033[0m",
		Prompt:          "\033[92mDERO Miner:\033[32m>>>\033[0m ",
		HistoryFile:     filepath.Join(os.TempDir(), "dero_miner_readline.tmp"),
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",

		HistorySearchFold:   true,
		FuncFilterInputRune: filterInput,
	})
	if err != nil {
		panic(err)
	}
	defer l.Close()

	// parse arguments and setup logging , print basic information
	exename, _ := os.Executable()
	f, err := os.Create(exename + ".log")
	if err != nil {
		fmt.Printf("Error while opening log file err: %s filename %s\n", err, exename+".log")
		return
	}
	globals.InitializeLog(l.Stdout(), f)
	logger = globals.Logger.WithName("miner")

	logger.Info("DERO Stargate HE AstroBWT miner : It is an alpha version, use it for testing/evaluations purpose only.")
	logger.Info("Copyright 2017-2026 DERO Project. All rights reserved.")
	logger.Info("", "OS", runtime.GOOS, "ARCH", runtime.GOARCH, "GOMAXPROCS", runtime.GOMAXPROCS(0))
	logger.Info("", "Version", config.Version.String())

	logger.V(1).Info("", "Arguments", globals.Arguments)

	globals.Initialize() // setup network and proxy

	logger.V(0).Info("", "MODE", globals.Config.Name)

	if globals.Arguments["--wallet-address"] != nil {
		addr, err := globals.ParseValidateAddress(globals.Arguments["--wallet-address"].(string))
		if err != nil {
			logger.Error(err, "Wallet address is invalid.")
			return
		}
		wallet_address = addr.String()
	}

	if !globals.Arguments["--testnet"].(bool) {
		daemon_rpc_address = "minernode1.dero.live:10100"
	} else {
		daemon_rpc_address = "127.0.0.1:10100"
	}

	if globals.Arguments["--daemon-rpc-address"] != nil {
		daemon_rpc_address = globals.Arguments["--daemon-rpc-address"].(string)
	}

	threads = runtime.GOMAXPROCS(0)
	if globals.Arguments["--mining-threads"] != nil {
		if s, err := strconv.Atoi(globals.Arguments["--mining-threads"].(string)); err == nil {
			threads = s
		} else {
			logger.Error(err, "Mining threads argument cannot be parsed.")
		}

		if threads > runtime.GOMAXPROCS(0) {
			logger.Info("Mining threads is more than available CPUs. This is NOT optimal", "thread_count", threads, "max_possible", runtime.GOMAXPROCS(0))
		}
	}

	if globals.Arguments["--bench"].(bool) {

		var wg sync.WaitGroup

		fmt.Printf("%20s %20s %20s %20s %20s \n", "Threads", "Total Time", "Total Iterations", "Time/PoW ", "Hash Rate/Sec")
		iterations = 1000
		for bench := 1; bench <= threads; bench++ {
			processor = 0
			now := time.Now()
			for i := 0; i < bench; i++ {
				wg.Add(1)
				go random_execution(&wg, iterations)
			}
			wg.Wait()
			duration := time.Now().Sub(now)

			fmt.Printf("%20s %20s %20s %20s %20s \n", fmt.Sprintf("%d", bench), fmt.Sprintf("%s", duration), fmt.Sprintf("%d", bench*iterations),
				fmt.Sprintf("%s", duration/time.Duration(bench*iterations)), fmt.Sprintf("%.1f", float32(time.Second)/(float32(duration/time.Duration(bench*iterations)))))

		}

		os.Exit(0)
	}

	logger.Info(fmt.Sprintf("System will mine to \"%s\" with %d threads. Good Luck!!", wallet_address, threads))

	//threads_ptr := flag.Int("threads", runtime.NumCPU(), "No. Of threads")
	//iterations_ptr := flag.Int("iterations", 20, "No. Of DERO Stereo POW calculated/thread")
	/*bench_ptr := flag.Bool("bench", false, "run bench with params")
	daemon_ptr := flag.String("rpc-server-address", "127.0.0.1:18091", "DERO daemon RPC address to get work and submit mined blocks")
	delay_ptr := flag.Int("delay", 1, "Fetch job every this many seconds")
	wallet_address := flag.String("wallet-address", "", "Owner of this wallet will receive mining rewards")

	_ = daemon_ptr
	_ = delay_ptr
	_ = wallet_address
	*/

	if threads < 1 || iterations < 1 || threads > 2048 {
		panic("Invalid parameters\n")
		//return
	}

	// This tiny goroutine continuously updates status as required
	go func() {
		last_our_height := int64(0)
		last_best_height := int64(0)

		last_counter := uint64(0)
		last_counter_time := time.Now()
		last_mining_state := false

		_ = last_mining_state

		mining := true
		for {
			select {
			case <-Exit_In_Progress:
				return
			default:
			}

			best_height := int64(0)
			// only update prompt if needed
			if last_our_height != our_height || last_best_height != best_height || last_counter != counter {
				// choose color based on urgency
				color := "\033[33m"  // default is green color
				pcolor := "\033[32m" // default is green color

				mining_string := ""

				if mining {
					mining_speed := float64(counter-last_counter) / (float64(uint64(time.Since(last_counter_time))) / 1000000000.0)
					last_counter = counter
					last_counter_time = time.Now()
					switch {
					case mining_speed > 1000000:
						mining_string = fmt.Sprintf("MINING @ %.3f MH/s", float32(mining_speed)/1000000.0)
					case mining_speed > 1000:
						mining_string = fmt.Sprintf("MINING @ %.3f KH/s", float32(mining_speed)/1000.0)
					case mining_speed > 0:
						mining_string = fmt.Sprintf("MINING @ %.0f H/s", mining_speed)
					}
				}
				last_mining_state = mining

				hash_rate_string := ""

				switch {
				case hash_rate > 1000000000000:
					hash_rate_string = fmt.Sprintf("%.3f TH/s", float64(hash_rate)/1000000000000.0)
				case hash_rate > 1000000000:
					hash_rate_string = fmt.Sprintf("%.3f GH/s", float64(hash_rate)/1000000000.0)
				case hash_rate > 1000000:
					hash_rate_string = fmt.Sprintf("%.3f MH/s", float64(hash_rate)/1000000.0)
				case hash_rate > 1000:
					hash_rate_string = fmt.Sprintf("%.3f KH/s", float64(hash_rate)/1000.0)
				case hash_rate > 0:
					hash_rate_string = fmt.Sprintf("%d H/s", hash_rate)
				}

				testnet_string := ""
				if !globals.IsMainnet() {
					testnet_string = "\033[31m TESTNET"
				}

				l.SetPrompt(fmt.Sprintf("\033[1m\033[32mDERO Miner: \033[0m"+color+"Height %d "+pcolor+" BLOCKS %d MiniBlocks %d Rejected %d StaleSubmits %d \033[32mNW %s %s>%s>>\033[0m ", our_height, block_counter, mini_block_counter, rejected, atomic.LoadUint64(&staleSubmitsDropped), hash_rate_string, mining_string, testnet_string))
				l.Refresh()
				last_our_height = our_height
				last_best_height = best_height
			}
			time.Sleep(1 * time.Second)
		}
	}()

	l.Refresh() // refresh the prompt

	go func() {
		var gracefulStop = make(chan os.Signal, 1)
		signal.Notify(gracefulStop, os.Interrupt) // listen to all signals
		for {
			sig := <-gracefulStop
			fmt.Printf("received signal %s\n", sig)

			if sig.String() == "interrupt" {
				close(Exit_In_Progress)
			}
		}
	}()

	if threads > 255 {
		logger.Error(nil, "This program supports maximum 256 CPU cores.", "available", threads)
		threads = 255
	}

	go getwork(wallet_address)
	go submitWorker()

	for i := 0; i < threads; i++ {
		go mineblock(i)
	}

	for {
		line, err := l.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				fmt.Print("Ctrl-C received, Exit in progress\n")
				close(Exit_In_Progress)
				os.Exit(0)
				break
			} else {
				continue
			}
		} else if err == io.EOF {
			<-Exit_In_Progress
			break
		}

		line = strings.TrimSpace(line)
		line_parts := strings.Fields(line)

		command := ""
		if len(line_parts) >= 1 {
			command = strings.ToLower(line_parts[0])
		}

		switch {
		case line == "help":
			usage(l.Stderr())

		case strings.HasPrefix(line, "say"):
			line := strings.TrimSpace(line[3:])
			if len(line) == 0 {
				fmt.Println("say what?")
				break
			}
		case command == "version":
			fmt.Printf("Version %s OS:%s ARCH:%s \n", config.Version.String(), runtime.GOOS, runtime.GOARCH)

		case strings.ToLower(line) == "bye":
			fallthrough
		case strings.ToLower(line) == "exit":
			fallthrough
		case strings.ToLower(line) == "quit":
			close(Exit_In_Progress)
			os.Exit(0)
		case line == "":
		default:
			fmt.Println("you said:", strconv.Quote(line))
		}
	}

	<-Exit_In_Progress

	return

}

func random_execution(wg *sync.WaitGroup, iterations int) {
	var workbuf [255]byte

	runtime.LockOSThread()
	//threadaffinity()

	scratch := astrobwt_fast.Pool.Get().(*astrobwt_fast.ScratchData)
	rand.Read(workbuf[:])
	_ = scratch

	for i := 0; i < iterations; i++ {
		//_ = astrobwt_fast.POW_optimized(workbuf[:], scratch)
		_ = astrobwtv3.AstroBWTv3(workbuf[:])
	}
	wg.Done()
	runtime.UnlockOSThread()
}

// continuously get work

var connection *websocket.Conn
var connection_mutex sync.Mutex

// connectionEpoch counts successful (re)connects, bumped under
// connection_mutex in the same critical section as the connection
// assignment itself. mineblock's submit closures capture the epoch
// alongside the job they're hashing against and re-check it immediately
// before WriteJSON, inside connection_mutex -- if a reconnect happened in
// between (found-hash to submit is not instantaneous), the job's JobID no
// longer belongs to whatever session "connection" now points at, and the
// server would silently reject it as stale. Closing that window is the
// point of this counter: skip the doomed submission instead of sending it
// into the void, and count it via staleSubmitsDropped so it's observable
// rather than a silent share loss.
var connectionEpoch uint64

// staleSubmitsDropped counts shares submitWorker declined to submit
// because connectionEpoch had moved past what the finding thread observed
// -- i.e. a reconnect happened in the found-hash-to-submit window. Purely
// observational (a non-zero count means the race is real on this host,
// not that anything is broken -- the alternative was a submission the
// server would have rejected anyway, just silently).
var staleSubmitsDropped uint64

// submitQueueOverflowed counts shares dropped because submitQueue was
// full. Distinct from staleSubmitsDropped: this means the submitter
// itself is stuck or badly behind (dead connection, network stall), not
// just that one share's connection moved on since it was found. Should
// stay at 0 in practice -- submitQueueSize is generous relative to how
// often shares are actually found.
var submitQueueOverflowed uint64

// shareSubmission is one found share queued for submission. epoch is the
// connectionEpoch value the finding thread observed when it started
// hashing the job this share is for -- see connectionEpoch's comment.
type shareSubmission struct {
	epoch       uint64
	jobID       string
	hashingBlob string
}

const submitQueueSize = 64

var submitQueue = make(chan shareSubmission, submitQueueSize)

// enqueueShare hands a found share off to submitWorker and returns
// immediately either way -- a mining thread that just found a share gets
// straight back to hashing instead of blocking on connection_mutex and a
// network write in its own hot loop. The non-blocking send means a full
// queue (submitQueueOverflowed) drops the share rather than stalling the
// hashing thread waiting for room.
func enqueueShare(epoch uint64, jobID, hashingBlob string) {
	select {
	case submitQueue <- shareSubmission{epoch: epoch, jobID: jobID, hashingBlob: hashingBlob}:
	default:
		atomic.AddUint64(&submitQueueOverflowed, 1)
	}
}

// submitWorker is the one goroutine that ever touches the network for
// share submission -- started once from main(), runs for the process
// lifetime. Keeping all submission I/O on a single goroutine, fed by
// enqueueShare, is what lets mining threads hand off a found share and
// move on instead of doing that I/O themselves.
func submitWorker() {
	for s := range submitQueue {
		if atomic.LoadUint64(&connectionEpoch) != s.epoch {
			atomic.AddUint64(&staleSubmitsDropped, 1)
			continue
		}
		func() {
			defer globals.Recover(1)
			connection_mutex.Lock()
			defer connection_mutex.Unlock()
			// connectionEpoch only advances on a *successful* dial (see
			// getwork), but a *failed* dial still assigns connection = nil
			// (websocket.Dial's return value on error) without bumping the
			// epoch -- so an epoch match alone doesn't guarantee connection
			// is non-nil: a job fetched before a since-failed reconnect
			// attempt can still carry the old, still-current epoch while
			// connection sits nil during the retry-sleep window. Found live
			// against the simulator (repeated kill/restart during mining):
			// WriteJSON on a nil *websocket.Conn panics, recovered here but
			// firing on every queued share for the whole 10s retry sleep --
			// not a crash, but not something to leave firing either.
			if connection == nil {
				atomic.AddUint64(&staleSubmitsDropped, 1)
				return
			}
			connection.WriteJSON(rpc.SubmitBlock_Params{JobID: s.jobID, MiniBlockhashing_blob: s.hashingBlob})
		}()
	}
}

func getwork(wallet_address string) {
	var err error

	for {

		u := url.URL{Scheme: "wss", Host: daemon_rpc_address, Path: "/ws/" + wallet_address}
		logger.Info("connecting to ", "url", u.String())

		dialer := websocket.DefaultDialer
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
		// Locked (previously wasn't): connection is read-modify-write from
		// mineblock's submit closures under connection_mutex, so assigning
		// it here needs the same lock, not just the epoch bump below --
		// otherwise this is a plain data race on top of the staleness one.
		connection_mutex.Lock()
		connection, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
		if err == nil {
			atomic.AddUint64(&connectionEpoch, 1)
		}
		connection_mutex.Unlock()
		if err != nil {
			logger.Error(err, "Error connecting to server", "server adress", daemon_rpc_address)
			logger.Info("Will try in 10 secs", "server adress", daemon_rpc_address)
			time.Sleep(10 * time.Second)

			continue
		}

		var result rpc.GetBlockTemplate_Result
	wait_for_another_job:

		if err = connection.ReadJSON(&result); err != nil {
			logger.Error(err, "connection error")
			continue
		}

		mutex.Lock()
		job = result
		job_counter++
		mutex.Unlock()
		if job.LastError != "" {
			logger.Error(nil, "received error", "err", job.LastError)
		}

		block_counter = job.Blocks
		mini_block_counter = job.MiniBlocks // note if the miner submits the job late, though his counter
		// will increase, but a block has been already found, so
		// orphan miniblocks may be there ( means they will not br rewarded)
		rejected = job.Rejected
		hash_rate = job.Difficultyuint64
		our_height = int64(job.Height)
		Difficulty = job.Difficultyuint64

		//fmt.Printf("recv: %+v diff %d\n", result, Difficulty)
		goto wait_for_another_job
	}

}

func mineblock(tid int) {
	var diff big.Int
	var work [block.MINIBLOCK_SIZE]byte

	var random_buf [12]byte

	rand.Read(random_buf[:])

	scratch := astrobwt_fast.Pool.Get().(*astrobwt_fast.ScratchData)

	time.Sleep(5 * time.Second)

	nonce_buf := work[block.MINIBLOCK_SIZE-5:] //since slices are linked, it modifies parent
	runtime.LockOSThread()
	threadaffinity()

	var local_job_counter int64

	i := uint32(0)

	for {
		mutex.RLock()
		myjob := job
		local_job_counter = job_counter
		mutex.RUnlock()
		// Captured here, re-checked by submitWorker right before each
		// WriteJSON: local_job_counter == job_counter (the loop condition
		// below) only guards against grinding on stale work, not against a
		// reconnect landing in the narrow window between finding a valid
		// hash and finishing its submission.
		local_connection_epoch := atomic.LoadUint64(&connectionEpoch)

		n, err := hex.Decode(work[:], []byte(myjob.Blockhashing_blob))
		if err != nil || n != block.MINIBLOCK_SIZE {
			logger.Error(err, "Blockwork could not be decoded successfully", "blockwork", myjob.Blockhashing_blob, "n", n, "job", myjob)
			time.Sleep(time.Second)
			continue
		}

		height := binary.BigEndian.Uint64(work[0:]) & 0x000000ffffffffff

		copy(work[block.MINIBLOCK_SIZE-12:], random_buf[:]) // add more randomization in the mix
		work[block.MINIBLOCK_SIZE-1] = byte(tid)

		diff.SetString(myjob.Difficulty, 10)

		if work[0]&0xf != 1 { // check  version
			logger.Error(nil, "Unknown version, please check for updates", "version", work[0]&0x1f)
			time.Sleep(time.Second)
			continue
		}

		if int64(height) < globals.Config.MAJOR_HF2_HEIGHT {
			for local_job_counter == job_counter { // update job when it comes, expected rate 1 per second
				i++
				binary.BigEndian.PutUint32(nonce_buf, i)

				powhash := astrobwt_fast.POW_optimized(work[:], scratch)
				atomic.AddUint64(&counter, 1)

				if CheckPowHashBig(powhash, &diff) == true { // note we are doing a local, NW might have moved meanwhile
					logger.V(1).Info("Successfully found DERO miniblock (going to submit)", "difficulty", myjob.Difficulty, "height", myjob.Height)
					enqueueShare(local_connection_epoch, myjob.JobID, fmt.Sprintf("%x", work[:]))
				}
			}
		} else {

			for local_job_counter == job_counter { // update job when it comes, expected rate 1 per second
				i++
				binary.BigEndian.PutUint32(nonce_buf, i)

				powhash := astrobwtv3.AstroBWTv3(work[:])
				atomic.AddUint64(&counter, 1)

				if CheckPowHashBig(powhash, &diff) == true { // note we are doing a local, NW might have moved meanwhile
					logger.V(1).Info("Successfully found DERO miniblock (going to submit)", "difficulty", myjob.Difficulty, "height", myjob.Height)
					enqueueShare(local_connection_epoch, myjob.JobID, fmt.Sprintf("%x", work[:]))
				}
			}

		}
	}
}

func usage(w io.Writer) {
	io.WriteString(w, "commands:\n")
	io.WriteString(w, "\t\033[1mhelp\033[0m\t\tthis help\n")
	io.WriteString(w, "\t\033[1mstatus\033[0m\t\tShow general information\n")
	io.WriteString(w, "\t\033[1mbye\033[0m\t\tQuit the miner\n")
	io.WriteString(w, "\t\033[1mversion\033[0m\t\tShow version\n")
	io.WriteString(w, "\t\033[1mexit\033[0m\t\tQuit the miner\n")
	io.WriteString(w, "\t\033[1mquit\033[0m\t\tQuit the miner\n")

}

var completer = readline.NewPrefixCompleter(
	readline.PcItem("help"),
	readline.PcItem("status"),
	readline.PcItem("version"),
	readline.PcItem("bye"),
	readline.PcItem("exit"),
	readline.PcItem("quit"),
)

func filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}
