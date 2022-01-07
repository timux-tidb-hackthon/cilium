// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package tidb

import (
	"testing"

	"github.com/cilium/cilium/proxylib/accesslog"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"

	// log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	// logging.ToggleDebugLogs(true)
	// log.SetLevel(log.DebugLevel)

	TestingT(t)
}

type TiDBSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&TiDBSuite{})

// Set up access log server and Library instance for all the test cases
func (s *TiDBSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *TiDBSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *TiDBSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *TiDBSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

func (s *TiDBSuite) TestTiDBOnDataIncomplete(c *C) {
	conn := s.ins.CheckNewConnectionOK(c, "tidb", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "no-policy")
	data := [][]byte{[]byte("READ xssss")}
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 1)
}

func (s *TiDBSuite) TestTiDBOnDataBasicPass(c *C) {

	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "tidb"
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "tidb", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "cp1")
	msg1 := "READ sssss\r\n"
	msg2 := "WRITE sssss\r\n"
	msg3 := "HALT\r\n"
	msg4 := "RESET\r\n"
	data := [][]byte{[]byte(msg1 + msg2 + msg3 + msg4)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(msg1),
		proxylib.PASS, len(msg2),
		proxylib.PASS, len(msg3),
		proxylib.PASS, len(msg4),
		proxylib.MORE, 1)
}

func (s *TiDBSuite) TestTiDBOnDataMultipleReq(c *C) {

	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "tidb"
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "tidb", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "cp1")
	msg1Part1 := "RE"
	msg1Part2 := "SET\r\n"
	data := [][]byte{[]byte(msg1Part1), []byte(msg1Part2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(msg1Part1+msg1Part2),
		proxylib.MORE, 1)
}

func (s *TiDBSuite) TestTiDBOnDataAllowDenyCmd(c *C) {

	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp2"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "tidb"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "cmd"
			  value: "READ"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "tidb", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "cp2")
	msg1 := "READ xssss\r\n"
	msg2 := "WRITE xssss\r\n"
	data := [][]byte{[]byte(msg1 + msg2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte("ERROR\r\n"),
		proxylib.PASS, len(msg1),
		proxylib.DROP, len(msg2),
		proxylib.MORE, 1)
}

func (s *TiDBSuite) TestTiDBOnDataAllowDenyRegex(c *C) {

	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp3"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "tidb"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "file"
			  value: "s.*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "tidb", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "cp3")
	msg1 := "READ ssss\r\n"
	msg2 := "WRITE yyyyy\r\n"
	data := [][]byte{[]byte(msg1 + msg2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte("ERROR\r\n"),
		proxylib.PASS, len(msg1),
		proxylib.DROP, len(msg2),
		proxylib.MORE, 1)
}
