package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

var (
	foreground string

	logging string

	interfaceName string
	network       string

	port int
)

type M struct {
	conn.Bind
}

func NewM() *M {
	return &M{Bind: conn.NewStdNetBind()}
}

func (m *M) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	log.Println("called...???")
	return m.Bind.Open(port)
}

const Version = "trees version baby"

func main() {
	flag.StringVar(&interfaceName, "i", "tun0", "Interface name")
	flag.StringVar(&foreground, "mode", "foreground", "Mode")
	flag.StringVar(&logging, "logging", "error", "how much logging to do")
	flag.StringVar(&network, "ip", "10.23.44.1/24", "ip address")

	flag.IntVar(&port, "port", 5182, "port to listen on")

	flag.Parse()

	// get log level (default: info)

	logLevel := func() int {
		switch logging {
		case "verbose", "debug":
			return device.LogLevelVerbose
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelError
	}()

	// open TUN device (or use supplied fd)

	tdev, err := func() (tun.Device, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		if tunFdStr == "" {
			return tun.CreateTUN(interfaceName, device.DefaultMTU)
		}

		// construct tun device from supplied fd

		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		err = unix.SetNonblock(int(fd), true)
		if err != nil {
			return nil, err
		}

		file := os.NewFile(uintptr(fd), "")
		return tun.CreateTUNFromFile(file, device.DefaultMTU)
	}()

	if err == nil {
		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	logger.Verbosef("Starting wireguard-go version %s", Version)

	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	// open UAPI file (or use supplied fd)

	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(interfaceName)
		}

		// use supplied fd

		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(fd), ""), nil
	}()
	if err != nil {
		logger.Errorf("UAPI listen error: %v", err)
		os.Exit(ExitSetupFailed)
		return
	}
	// daemonize the process

	if foreground != "foreground" {
		env := os.Environ()
		env = append(env, fmt.Sprintf("%s=3", ENV_WG_TUN_FD))
		env = append(env, fmt.Sprintf("%s=4", ENV_WG_UAPI_FD))
		env = append(env, fmt.Sprintf("%s=1", ENV_WG_PROCESS_FOREGROUND))
		files := [3]*os.File{}
		if os.Getenv("LOG_LEVEL") != "" && logLevel != device.LogLevelSilent {
			files[0], _ = os.Open(os.DevNull)
			files[1] = os.Stdout
			files[2] = os.Stderr
		} else {
			files[0], _ = os.Open(os.DevNull)
			files[1], _ = os.Open(os.DevNull)
			files[2], _ = os.Open(os.DevNull)
		}
		attr := &os.ProcAttr{
			Files: []*os.File{
				files[0], // stdin
				files[1], // stdout
				files[2], // stderr
				tdev.File(),
				fileUAPI,
			},
			Dir: ".",
			Env: env,
		}

		path, err := os.Executable()
		if err != nil {
			logger.Errorf("Failed to determine executable: %v", err)
			os.Exit(ExitSetupFailed)
		}

		process, err := os.StartProcess(
			path,
			os.Args,
			attr,
		)
		if err != nil {
			logger.Errorf("Failed to daemonize: %v", err)
			os.Exit(ExitSetupFailed)
		}
		process.Release()
		return
	}

	tdev = NewWrap(tdev)

	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Errorf("failed to generate private key: %s", err)
		return
	}

	privateKey := hex.EncodeToString(k[:])

	log.Println("public key: ", k.PublicKey())
	log.Println("port: ", port)

	device := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	err = device.IpcSet(fmt.Sprintf(`private_key=%s
listen_port=%d
`, privateKey, port))
	if err != nil {
		log.Println("failed to set: ", err)
	}

	logger.Verbosef("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Errorf("Failed to listen on uapi socket: %v", err)
		os.Exit(ExitSetupFailed)
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	logger.Verbosef("UAPI listener started")

	err = func(network string) error {

		conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
		if err != nil {
			return err
		}
		defer conn.Close()

		ip, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			return err
		}

		ipNet.IP = ip

		err = setIp(conn, interfaceName, *ipNet)
		if err != nil {
			return err
		}

		return setUp(conn, interfaceName)
	}(network)
	if err != nil {
		log.Fatal("unable to set wireguard tunnel ip: ", err)
	}

	go func() {
		for e := range tdev.Events() {
			log.Println("go event: ", e)
		}
	}()

	err = device.Up()
	if err != nil {
		log.Println("unable to bring device up: ", err)
	}

	// wait for program to terminate

	signal.Notify(term, unix.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	uapi.Close()
	device.Close()

	logger.Verbosef("Shutting down")
}
