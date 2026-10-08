package migrate

import (
	"reflect"
	"testing"
)

func TestStatements(t *testing.T) {
	in := "-- comment\nCREATE TABLE a (id INT);\n\n-- x\nINSERT INTO a VALUES (1);\n"
	want := []string{"CREATE TABLE a (id INT)", "INSERT INTO a VALUES (1)"}
	if got := Statements(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}
