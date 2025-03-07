// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package tidbsql

import (
	"testing"

	"github.com/cilium/cilium/proxylib/accesslog"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"

	// "github.com/cilium/cilium/pkg/logging"
	// "fmt"
	log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	// logging.ToggleDebugLogs(true)
	log.SetLevel(log.DebugLevel)

	TestingT(t)
}

type TiDBSQLSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&TiDBSQLSuite{})

// Set up access log server and Library instance for all the test cases
func (s *TiDBSQLSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *TiDBSQLSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *TiDBSQLSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *TiDBSQLSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

func (s *TiDBSQLSuite) TestTiDBSQLOnDataIncomplete(c *C) {
	conn := s.ins.CheckNewConnectionOK(c, "tidbsql", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "no-policy")
	header := []byte{0x0f, 0x00, 0x00, 0x00, 0x03}
	header = append(header, []byte("show database")...)
	data := [][]byte{header}
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 1)
}

func buildMsg(msg string) []byte {
	msgLen := len(msg) + 1
	header := []byte{byte(msgLen), 0x00, 0x00, 0x00, 0x03}
	return append(header, []byte(msg)...)
}

func (s *TiDBSQLSuite) TestTiDBSQLOnDataBasicPass(c *C) {

	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "tidbsql"
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "tidbsql", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "cp1")

	msg1 := buildMsg("select * from t")
	conn.CheckOnDataOK(c, false, false, &[][]byte{msg1}, []byte{}, proxylib.PASS, len(msg1))
	msg2 := buildMsg("insert into t (id, name, year) values (1, 'hackthon', 2021)")
	conn.CheckOnDataOK(c, false, false, &[][]byte{msg2}, []byte{}, proxylib.PASS, len(msg2))
	msg3 := buildMsg("update t set name='hackathon' where id=1")
	conn.CheckOnDataOK(c, false, false, &[][]byte{msg3}, []byte{}, proxylib.PASS, len(msg3))
	msg4 := buildMsg("delete from t")
	conn.CheckOnDataOK(c, false, false, &[][]byte{msg4}, []byte{}, proxylib.PASS, len(msg4))
}

func (s *TiDBSQLSuite) TestTiDBSQLPrepareReq(c *C) {}

func (s *TiDBSQLSuite) TestTiDBSQLOnDataInjection(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp3"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "tidbsql"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "select"
			  value: "test.*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "tidbsql", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "cp3")
	// request body
	stmt1 := "SELECT a, b FROM allow_database"
	data := [][]byte{constructStmtBytesArray(stmt1)}
	// []byte("") is the expectedResult
	conn.CheckOnDataOK(c, false, false, &data, []byte(""), // expect result
		proxylib.PASS, len(stmt1)+4)
	stmt2 := "SELECT a, b FROM deny_database"
	data = [][]byte{constructStmtBytesArray(stmt2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte("ERROR\r\n"), // expect result
		proxylib.DROP, len(stmt2)+4) // ops result, length)
}

func constructStmtBytesArray(stmt string) []byte {
	// https://dev.mysql.com/doc/internals/en/mysql-packet.html#packet-Protocol::Packet
	ops := []byte{3} // COM_QUERY, https://dev.mysql.com/doc/internals/en/com-query.html
	payload := append(ops, []byte(stmt)...)
	payloadLength := len(payload)
	sequenceID := 0
	return append([]byte{byte(payloadLength), 0, 0 /*payload length, assume payload < 255*/, byte(sequenceID)}, payload...)
}
