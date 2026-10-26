package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/wantox86/KangPaket-server/internal/auth"
	"github.com/wantox86/KangPaket-server/internal/config"
	"github.com/wantox86/KangPaket-server/internal/db"
)

const usage = `usage: kangpaket-server [command]

With no command the API server starts. Commands (password is read from stdin, never from arguments):
  create-user --username NAME [--admin]
  set-password --username NAME
  disable-user --username NAME
  enable-user  --username NAME
  delete-user  --username NAME
  list-users`

func runCLI(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	username := fs.String("username", "", "username")
	admin := fs.Bool("admin", false, "grant admin (create-user)")
	switch cmd {
	case "create-user", "set-password", "disable-user", "enable-user", "delete-user", "list-users":
	case "help", "-h", "--help":
		fmt.Println(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n%s", cmd, usage)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if cmd != "list-users" && *username == "" {
		return errors.New("--username is required")
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, err := db.Open(ctx, cfg.DSN())
	if err != nil {
		return err
	}
	defer conn.Close()
	svc, err := newAuthService(cfg, conn, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}

	switch cmd {
	case "create-user":
		pw, err := readPassword(true)
		if err != nil {
			return err
		}
		u, err := svc.CreateUser(ctx, *username, pw, *admin)
		if err != nil {
			return describe(err)
		}
		fmt.Printf("created user %q (id=%d, admin=%t)\n", u.Username, u.ID, u.IsAdmin)
	case "set-password":
		pw, err := readPassword(true)
		if err != nil {
			return err
		}
		if err := svc.SetPassword(ctx, *username, pw); err != nil {
			return describe(err)
		}
		fmt.Println("password updated; existing sessions revoked")
	case "disable-user", "enable-user":
		if err := svc.SetDisabled(ctx, *username, cmd == "disable-user"); err != nil {
			return describe(err)
		}
		fmt.Println("ok")
	case "delete-user":
		if err := svc.Store.DeleteUser(ctx, auth.NormalizeUsername(*username)); err != nil {
			return describe(err)
		}
		fmt.Println("deleted")
	case "list-users":
		users, err := svc.Store.ListUsers(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tUSERNAME\tADMIN\tDISABLED\tCREATED")
		for _, u := range users {
			fmt.Fprintf(tw, "%d\t%s\t%t\t%t\t%s\n", u.ID, u.Username, u.IsAdmin, u.Disabled, u.CreatedAt.Format(time.RFC3339))
		}
		tw.Flush()
	}
	return nil
}

func describe(err error) error {
	switch {
	case errors.Is(err, auth.ErrInvalidUsername):
		return errors.New("username must be 3-32 chars of a-z 0-9 . _ -")
	case errors.Is(err, auth.ErrWeakPassword):
		return fmt.Errorf("password must be %d-256 characters", auth.MinPasswordLen)
	case errors.Is(err, auth.ErrUsernameTaken):
		return errors.New("username already exists")
	case errors.Is(err, auth.ErrNotFound):
		return errors.New("user not found")
	}
	return err
}

// readPassword prompts without echo on a TTY (twice when confirm is set);
// otherwise it reads one line from stdin so it works with `docker exec -i`.
func readPassword(confirm bool) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Password: ")
		a, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if confirm {
			fmt.Fprint(os.Stderr, "Repeat password: ")
			b, err := term.ReadPassword(fd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			if string(a) != string(b) {
				return "", errors.New("passwords do not match")
			}
		}
		return string(a), nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", errors.New("no password on stdin")
	}
	return strings.TrimRight(line, "\r\n"), nil
}
