package main

import (
	"fmt"

	"github.com/pingcap/tidb/parser"
	"github.com/pingcap/tidb/parser/ast"
	_ "github.com/pingcap/tidb/parser/test_driver"
)

func parse(sql string) (ast.StmtNode, error) {
	p := parser.New()

	stmtNodes, _, err := p.Parse(sql, "", "")
	if err != nil {
		return nil, err
	}

	return stmtNodes[0], nil
}

func getDatabaseTables(sql string) (database string, table string, err error) {
	astNode, err := parse(sql)
	if err != nil {
		fmt.Printf("parse error: %v\n", err.Error())
		return
	}

	switch v := astNode.(type) {
	case *ast.SelectStmt:
		table := astNode.(*ast.SelectStmt).From.TableRefs.Left.(*ast.TableSource).Source.(*ast.TableName)
		return table.Name.String(), table.Schema.String(), nil
	default:
		fmt.Println(v)
	}
	return
}

func main() {
	database, table, _ := getDatabaseTables("SELECT a, b FROM database.t")
	fmt.Println(database, table)
}
