package vhmaskd

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// export interface
type IAuth interface {
	HandleAuth(conn *net.Conn) (*net.Addr, *time.Time, error)
}

type EventAuthenticated struct {
	Addr       *net.Addr
	expireTime time.Time
}

type VHMaskdService struct {
	RequestedServicePort int
	ServicePort          int
	MaskedPort           int
	Running              bool
	Auth                 *IAuth
	iptables             *IPTables
	eventsChan           chan interface{}
}

func NewVHMaskdService(servicePort, maskedPort int, auth IAuth) *VHMaskdService {
	return &VHMaskdService{
		RequestedServicePort: servicePort,
		MaskedPort:           maskedPort,
		Auth:                 &auth,
		eventsChan:           make(chan interface{}, 128),
	}
}

func (s *VHMaskdService) handleConnection(conn *net.Conn) {
	defer (*conn).Close()
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic: ", r)
		}
	}()
	if authenticatedAddr, expire, err := (*s.Auth).HandleAuth(conn); err != nil {
		fmt.Println(err)
	} else if authenticatedAddr == nil {
		fmt.Println("Failed attempt to authenticate from " + (*conn).RemoteAddr().String())
	} else {
		if expire == nil {
			expire = new(time.Time)
			*expire = time.Now().Add(15 * time.Second)
		}
		fmt.Println("Authenticated " + (*conn).RemoteAddr().String() + " until " + (*expire).Format(time.RFC3339))
		s.eventsChan <- EventAuthenticated{Addr: authenticatedAddr, expireTime: *expire}
	}
}

func timerStopAndCleanup(t *time.Timer) {
	if !t.Stop() {
		<-t.C
	}
}

func (s *VHMaskdService) syncIPTables(clients map[net.Addr]time.Time) {
	authorizedClients := make([]net.Addr, 0, len(clients))
	for addr := range clients {
		authorizedClients = append(authorizedClients, addr)
	}
	fmt.Printf("Syncing iptables: %v\n", authorizedClients)
	s.iptables.SyncAuthorizedIps(authorizedClients)
}

func (s *VHMaskdService) internalEvents(finishedSignal chan bool) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	timer := time.NewTimer(1 * time.Second)
	defer timerStopAndCleanup(timer)

	nextTimerCall := time.Now().Add(1 * time.Second)

	authenticatedClients := make(map[net.Addr]time.Time)

	lastAppliedConfigurationVersion := 0
	configurationVersion := 7

	s.iptables.Setup()
	defer func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("Recovered from panic: ", r)
			}
			finishedSignal <- true
		}()
		s.iptables.Teardown()
	}()

	for s.Running {
		if lastAppliedConfigurationVersion != configurationVersion {
			lastAppliedConfigurationVersion = configurationVersion
			s.syncIPTables(authenticatedClients)
		}
		select {
		case <-sigs:
			fmt.Println("Received signal, shutting down")
			s.Running = false
		case event := <-s.eventsChan:
			switch e := event.(type) {
			case EventAuthenticated:
				fmt.Println("Received authenticated event")
				authenticatedClients[*e.Addr] = e.expireTime
				configurationVersion = (configurationVersion + 1) % 13371337
				if nextTimerCall.After(e.expireTime) {
					nextTimerCall = e.expireTime
					timerStopAndCleanup(timer)
					timer.Reset(time.Until(e.expireTime))
				}
			default:
				fmt.Println("Unknown event type")
			}
		case <-timer.C:
			for {
				fmt.Println("Process timer event")
				now := time.Now()
				nextCall := now.Add(133773311337 * time.Millisecond)
				expiringClients := make([]net.Addr, 0)
				for addr, exp := range authenticatedClients {
					if !exp.After(now) {
						expiringClients = append(expiringClients, addr)
					} else if exp.Before(nextCall) {
						nextCall = exp
					}
				}
				if len(expiringClients) > 0 {
					configurationVersion = (configurationVersion + 1) % 13371337
					for _, addr := range expiringClients {
						delete(authenticatedClients, addr)
					}
				}
				// we dont need to do time calculation too be so precise
				now = time.Now()
				if nextCall.After(now) {
					nextTimerCall = nextCall
					timer.Reset(nextCall.Sub(now))
					break
				}
			}
		}
	}
}

func (s *VHMaskdService) Run() error {
	var err error
	var server net.Listener
	if server, err = net.Listen("tcp", ":"+strconv.Itoa(s.RequestedServicePort)); err != nil {
		panic(err)
	}

	if s.RequestedServicePort == 0 {
		s.ServicePort = server.Addr().(*net.TCPAddr).Port
	} else {
		s.ServicePort = s.RequestedServicePort
	}
	s.iptables = NewIPTables(
		"vhmaskd_"+strconv.Itoa(s.MaskedPort),
		s.ServicePort, s.MaskedPort,
	)
	defer func() {
		s.iptables = nil
	}()
	fmt.Printf("Server is listening on port %v, protecting port %v\n", s.ServicePort, s.MaskedPort)
	s.Running = true
	finishedSignal := make(chan bool)
	clientHandlerFinishedSignal := make(chan bool)
	go s.internalEvents(finishedSignal)
	go func() {
		for s.Running {
			conn, err := server.Accept()
			if !s.Running {
				break
			}
			if err != nil {
				fmt.Println(err)
			} else {
				go s.handleConnection(&conn)
			}
		}

		clientHandlerFinishedSignal <- true
	}()
	<-finishedSignal
	server.Close()
	<-clientHandlerFinishedSignal
	fmt.Println("Good bye")
	return nil
}
