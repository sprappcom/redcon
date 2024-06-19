// Package redcon implements a Redis compatible server framework
package redcon

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/sprappcom/redhub/pkg/resp"
	"github.com/tidwall/btree"
	"github.com/tidwall/match"
)

type Action int

const (
	None Action = iota
	Close
	Shutdown
)

type Conn struct {
	gnet.Conn
	buf bytes.Buffer
}

func (c *Conn) WriteArray(count int) {
	c.buf.Write(resp.AppendArray(nil, count))
}

func (c *Conn) WriteBulkString(bulk string) {
	c.buf.Write(resp.AppendBulkString(nil, bulk))
}

func (c *Conn) WriteString(str string) {
	c.buf.Write(resp.AppendString(nil, str))
}

func (c *Conn) WriteInt(num int) {
	c.buf.Write(resp.AppendInt(nil, int64(num)))
}

func (c *Conn) WriteNull() {
	c.buf.Write(resp.AppendNull(nil))
}

func (c *Conn) Flush() error {
	_, err := c.Conn.Write(c.buf.Bytes())
	c.buf.Reset()
	return err
}

func (c *Conn) ReadCommand() (resp.Command, error) {
	data, err := c.Conn.Next(-1)
	if err != nil {
		return resp.Command{}, err
	}
	c.buf.Write(data)
	cmds, _, err := resp.ReadCommands(c.buf.Bytes())
	if err != nil {
		return resp.Command{}, err
	}
	if len(cmds) > 0 {
		cmd := cmds[0]
		c.buf.Next(len(cmd.Raw))
		return cmd, nil
	}
	return resp.Command{}, fmt.Errorf("no command")
}

func (c *Conn) WriteError(msg string) {
	c.buf.Write(resp.AppendError(nil, msg))
}

type Options struct {
	Multicore        bool
	LockOSThread     bool
	ReadBufferCap    int
	LB               gnet.LoadBalancing
	NumEventLoop     int
	ReusePort        bool
	Ticker           bool
	TCPKeepAlive     int
	TCPNoDelay       gnet.TCPSocketOpt
	SocketRecvBuffer int
	SocketSendBuffer int
	TLSConfig        *tls.Config
}

func NewRedHub(
	onOpened func(c *Conn) (out []byte, action Action),
	onClosed func(c *Conn, err error) (action Action),
	handler func(cmd resp.Command, out []byte) ([]byte, Action),
) *redHub {
	return &redHub{
		redHubBufMap: make(map[gnet.Conn]*connBuffer),
		connSync:     sync.RWMutex{},
		onOpened:     onOpened,
		onClosed:     onClosed,
		handler:      handler,
		pubsub:       NewPubSub(),
	}
}

type redHub struct {
	gnet.BuiltinEventEngine
	eng          gnet.Engine
	onOpened     func(c *Conn) (out []byte, action Action)
	onClosed     func(c *Conn, err error) (action Action)
	handler      func(cmd resp.Command, out []byte) ([]byte, Action)
	redHubBufMap map[gnet.Conn]*connBuffer
	connSync     sync.RWMutex
	pubsub       *PubSub
}

type connBuffer struct {
	buf     bytes.Buffer
	command []resp.Command
}

func (rs *redHub) OnBoot(eng gnet.Engine) gnet.Action {
	rs.eng = eng
	return gnet.None
}

func (rs *redHub) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	rs.connSync.Lock()
	defer rs.connSync.Unlock()
	rs.redHubBufMap[c] = new(connBuffer)
	rs.onOpened(&Conn{Conn: c})
	return
}

func (rs *redHub) OnClose(c gnet.Conn, err error) (action gnet.Action) {
	rs.connSync.Lock()
	defer rs.connSync.Unlock()
	delete(rs.redHubBufMap, c)
	rs.onClosed(&Conn{Conn: c}, err)
	return gnet.None
}

func (rs *redHub) OnTraffic(c gnet.Conn) gnet.Action {
	rs.connSync.RLock()
	defer rs.connSync.RUnlock()
	cb, ok := rs.redHubBufMap[c]
	if !ok {
		out := resp.AppendError(nil, "ERR Client is closed")
		c.Write(out)
		return gnet.Close
	}
	frame, _ := c.Next(-1)
	cb.buf.Write(frame)
	cmds, lastbyte, err := resp.ReadCommands(cb.buf.Bytes())
	if err != nil {
		out := resp.AppendError(nil, "ERR "+err.Error())
		c.Write(out)
		return gnet.None
	}
	cb.command = append(cb.command, cmds...)
	cb.buf.Reset()
	if len(lastbyte) == 0 {
		var status Action
		var out []byte
		for len(cb.command) > 0 {
			cmd := cb.command[0]
			if len(cb.command) == 1 {
				cb.command = nil
			} else {
				cb.command = cb.command[1:]
			}
			cmd.Conn = &Conn{Conn: c}
			out, status = rs.handler(cmd, out)
			c.Write(out)
			switch status {
			case Close:
				return gnet.Close
			}
		}
	} else {
		cb.buf.Write(lastbyte)
	}
	return gnet.None
}

func ListenAndServe(addr string, options Options, rh *redHub) error {
	opts := []gnet.Option{
		gnet.WithMulticore(options.Multicore),
		gnet.WithLockOSThread(options.LockOSThread),
		gnet.WithReadBufferCap(options.ReadBufferCap),
		gnet.WithLoadBalancing(options.LB),
		gnet.WithNumEventLoop(options.NumEventLoop),
		gnet.WithReusePort(options.ReusePort),
		gnet.WithTicker(options.Ticker),
		gnet.WithTCPKeepAlive(time.Duration(options.TCPKeepAlive) * time.Second),
		gnet.WithTCPNoDelay(options.TCPNoDelay),
		gnet.WithSocketRecvBuffer(options.SocketRecvBuffer),
		gnet.WithSocketSendBuffer(options.SocketSendBuffer),
	}

	if options.TLSConfig != nil {
		return gnet.Run(rh, addr, opts...)
	}
	return gnet.Run(rh, addr, opts...)
}

// PubSub related code

type PubSub struct {
	mu     sync.RWMutex
	nextid uint64
	initd  bool
	chans  *btree.BTree
	conns  map[*Conn]*pubSubConn
}

func NewPubSub() *PubSub {
	return &PubSub{
		chans: btree.New(byEntry),
		conns: make(map[*Conn]*pubSubConn),
	}
}

type pubSubConn struct {
	id      uint64
	mu      sync.Mutex
	conn    *Conn
	dconn   *Conn
	entries map[*pubSubEntry]bool
}

type pubSubEntry struct {
	pattern bool
	sconn   *pubSubConn
	channel string
}

func byEntry(a, b interface{}) bool {
	aa := a.(*pubSubEntry)
	bb := b.(*pubSubEntry)
	if !aa.pattern && bb.pattern {
		return true
	}
	if aa.pattern && !bb.pattern {
		return false
	}
	if aa.channel < bb.channel {
		return true
	}
	if aa.channel > bb.channel {
		return false
	}
	var aid uint64
	var bid uint64
	if aa.sconn != nil {
		aid = aa.sconn.id
	}
	if bb.sconn != nil {
		bid = bb.sconn.id
	}
	return aid < bid
}

func (ps *PubSub) Subscribe(conn *Conn, channel string) {
	ps.subscribe(conn, false, channel)
}

func (ps *PubSub) Psubscribe(conn *Conn, channel string) {
	ps.subscribe(conn, true, channel)
}

func (ps *PubSub) Publish(channel, message string) int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if !ps.initd {
		return 0
	}
	var sent int
	pivot := &pubSubEntry{pattern: false, channel: channel}
	ps.chans.Ascend(pivot, func(item interface{}) bool {
		entry := item.(*pubSubEntry)
		if entry.channel != pivot.channel || entry.pattern != pivot.pattern {
			return false
		}
		entry.sconn.writeMessage(entry.pattern, "", channel, message)
		sent++
		return true
	})

	pivot = &pubSubEntry{pattern: true}
	ps.chans.Ascend(pivot, func(item interface{}) bool {
		entry := item.(*pubSubEntry)
		if match.Match(channel, entry.channel) {
			entry.sconn.writeMessage(entry.pattern, entry.channel, channel, message)
			sent++
		}
		return true
	})

	return sent
}

func (sconn *pubSubConn) writeMessage(pat bool, pchan, channel, msg string) {
	sconn.mu.Lock()
	defer sconn.mu.Unlock()
	if pat {
		sconn.dconn.WriteArray(4)
		sconn.dconn.WriteBulkString("pmessage")
		sconn.dconn.WriteBulkString(pchan)
		sconn.dconn.WriteBulkString(channel)
		sconn.dconn.WriteBulkString(msg)
	} else {
		sconn.dconn.WriteArray(3)
		sconn.dconn.WriteBulkString("message")
		sconn.dconn.WriteBulkString(channel)
		sconn.dconn.WriteBulkString(msg)
	}
	sconn.dconn.Flush()
}

func (sconn *pubSubConn) bgrunner(ps *PubSub) {
	defer func() {
		ps.mu.Lock()
		defer ps.mu.Unlock()
		for entry := range sconn.entries {
			ps.chans.Delete(entry)
		}
		delete(ps.conns, sconn.conn)
		sconn.mu.Lock()
		defer sconn.mu.Unlock()
		sconn.dconn.Close()
	}()
	for {
		cmd, err := sconn.dconn.ReadCommand()
		if err != nil {
			return
		}
		if len(cmd.Args) == 0 {
			continue
		}
		switch strings.ToLower(string(cmd.Args[0])) {
		case "psubscribe", "subscribe":
			if len(cmd.Args) < 2 {
				sconn.mu.Lock()
				sconn.dconn.WriteError(fmt.Sprintf("ERR wrong number of arguments for '%s'", cmd.Args[0]))
				sconn.dconn.Flush()
				sconn.mu.Unlock()
				continue
			}
			command := strings.ToLower(string(cmd.Args[0]))
			for i := 1; i < len(cmd.Args); i++ {
				if command == "psubscribe" {
					ps.Psubscribe(sconn.conn, string(cmd.Args[i]))
				} else {
					ps.Subscribe(sconn.conn, string(cmd.Args[i]))
				}
			}
		case "unsubscribe", "punsubscribe":
			pattern := strings.ToLower(string(cmd.Args[0])) == "punsubscribe"
			if len(cmd.Args) == 1 {
				ps.unsubscribe(sconn.conn, pattern, true, "")
			} else {
				for i := 1; i < len(cmd.Args); i++ {
					channel := string(cmd.Args[i])
					ps.unsubscribe(sconn.conn, pattern, false, channel)
				}
			}
		case "quit":
			sconn.mu.Lock()
			sconn.dconn.WriteString("OK")
			sconn.dconn.Flush()
			sconn.dconn.Close()
			sconn.mu.Unlock()
			return
		case "ping":
			var msg string
			switch len(cmd.Args) {
			case 1:
			case 2:
				msg = string(cmd.Args[1])
			default:
				sconn.mu.Lock()
				sconn.dconn.WriteError(fmt.Sprintf("ERR wrong number of arguments for '%s'", cmd.Args[0]))
				sconn.dconn.Flush()
				sconn.mu.Unlock()
				continue
			}
			sconn.mu.Lock()
			sconn.dconn.WriteArray(2)
			sconn.dconn.WriteBulkString("pong")
			sconn.dconn.WriteBulkString(msg)
			sconn.dconn.Flush()
			sconn.mu.Unlock()
		default:
			sconn.mu.Lock()
			sconn.dconn.WriteError(fmt.Sprintf("ERR Can't execute '%s': only (P)SUBSCRIBE / (P)UNSUBSCRIBE / PING / QUIT are allowed in this context", cmd.Args[0]))
			sconn.dconn.Flush()
			sconn.mu.Unlock()
		}
	}
}

func (ps *PubSub) subscribe(conn *Conn, pattern bool, channel string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if !ps.initd {
		ps.conns = make(map[*Conn]*pubSubConn)
		ps.chans = btree.New(byEntry)
		ps.initd = true
	}

	sconn, ok := ps.conns[conn]
	if !ok {
		ps.nextid++
		sconn = &pubSubConn{
			id:      ps.nextid,
			conn:    conn,
			dconn:   conn,
			entries: make(map[*pubSubEntry]bool),
		}
		ps.conns[conn] = sconn
	}
	sconn.mu.Lock()
	defer sconn.mu.Unlock()

	entry := &pubSubEntry{
		pattern: pattern,
		channel: channel,
		sconn:   sconn,
	}
	ps.chans.Set(entry)
	sconn.entries[entry] = true

	sconn.dconn.WriteArray(3)
	if pattern {
		sconn.dconn.WriteBulkString("psubscribe")
	} else {
		sconn.dconn.WriteBulkString("subscribe")
	}
	sconn.dconn.WriteBulkString(channel)
	var count int
	for entry := range sconn.entries {
		if entry.pattern == pattern {
			count++
		}
	}
	sconn.dconn.WriteInt(count)
	sconn.dconn.Flush()

	if !ok {
		go sconn.bgrunner(ps)
	}
}

func (ps *PubSub) unsubscribe(conn *Conn, pattern, all bool, channel string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	sconn := ps.conns[conn]
	sconn.mu.Lock()
	defer sconn.mu.Unlock()

	removeEntry := func(entry *pubSubEntry) {
		if entry != nil {
			ps.chans.Delete(entry)
			delete(sconn.entries, entry)
		}
		sconn.dconn.WriteArray(3)
		if pattern {
			sconn.dconn.WriteBulkString("punsubscribe")
		} else {
			sconn.dconn.WriteBulkString("unsubscribe")
		}
		if entry != nil {
			sconn.dconn.WriteBulkString(entry.channel)
		} else {
			sconn.dconn.WriteNull()
		}
		var count int
		for entry := range sconn.entries {
			if entry.pattern == pattern {
				count++
			}
		}
		sconn.dconn.WriteInt(count)
	}
	if all {
		var entries []*pubSubEntry
		for entry := range sconn.entries {
			if entry.pattern == pattern {
				entries = append(entries, entry)
			}
		}
		if len(entries) == 0 {
			removeEntry(nil)
		} else {
			for _, entry := range entries {
				removeEntry(entry)
			}
		}
	} else {
		for entry := range sconn.entries {
			if entry.pattern == pattern && entry.channel == channel {
				removeEntry(entry)
				break
			}
		}
	}
	sconn.dconn.Flush()
}
