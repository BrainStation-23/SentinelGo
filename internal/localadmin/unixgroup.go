package localadmin

// macOS (the admin group, dseditgroup) and Linux (sudo or wheel, gpasswd),
// as the backend's scripts do it.

import (
	"context"
	"fmt"
	"strings"
)

// ── macOS ────────────────────────────────────────────────────────────────────

type darwinGroup struct {
	run  Runner
	self string
}

func (g *darwinGroup) checkMember(ctx context.Context, m string) bool {
	_, err := g.run(ctx, "dseditgroup", []string{"-o", "checkmember", "-m", m, "admin"}, nil)
	return err == nil
}

func (g *darwinGroup) IsMember(ctx context.Context, r Request) (bool, error) {
	m, err := unixName(r.Member)
	if err != nil {
		return false, err
	}
	return g.checkMember(ctx, m), nil
}

func (g *darwinGroup) Add(ctx context.Context, r Request) (Outcome, error) {
	m, err := unixName(r.Member)
	if err != nil {
		return Outcome{}, err
	}
	if _, err := g.run(ctx, "id", []string{m}, nil); err != nil {
		return Outcome{}, fmt.Errorf("no account %s on this Mac", m)
	}
	if g.checkMember(ctx, m) {
		return Outcome{Success: true, State: StateAlready, Member: m}, nil
	}
	if _, err := g.run(ctx, "dseditgroup", []string{"-o", "edit", "-a", m, "-t", "user", "admin"}, nil); err != nil {
		return Outcome{}, fmt.Errorf("dseditgroup couldn't add %s: %w", m, err)
	}
	if !g.checkMember(ctx, m) {
		return Outcome{}, fmt.Errorf("%s is still not an administrator", m)
	}
	return Outcome{Success: true, State: StateAdded, Member: m}, nil
}

func (g *darwinGroup) Remove(ctx context.Context, r Request) (Outcome, error) {
	m, err := unixName(r.Member)
	if err != nil {
		return Outcome{}, err
	}
	switch {
	case m == "root":
		return Outcome{}, ErrRoot
	case g.self != "" && m == g.self:
		return Outcome{}, ErrOwnAccount
	}
	if !g.checkMember(ctx, m) {
		return Outcome{Success: true, State: StateAbsent, Member: m}, nil
	}
	out, err := g.run(ctx, "dscl", []string{".", "-read", "/Groups/admin", "GroupMembership"}, nil)
	if err != nil {
		return Outcome{}, fmt.Errorf("couldn't list the administrators: %w", err)
	}
	others := 0
	_, list, _ := strings.Cut(out, ":")
	for _, u := range strings.Fields(list) {
		if u != "root" && u != m {
			others++
		}
	}
	if others == 0 {
		return Outcome{}, lastAdminError(m)
	}
	if _, err := g.run(ctx, "dseditgroup", []string{"-o", "edit", "-d", m, "-t", "user", "admin"}, nil); err != nil {
		return Outcome{}, fmt.Errorf("dseditgroup couldn't remove %s: %w", m, err)
	}
	res := Outcome{Success: true, State: StateRemoved, Member: m}
	n := 0
	if r.SignOut {
		if uid, err := g.run(ctx, "id", []string{"-u", m}, nil); err == nil {
			if _, err := g.run(ctx, "launchctl", []string{"bootout", "gui/" + strings.TrimSpace(uid)}, nil); err == nil {
				n = 1
			}
		}
	}
	res.SignedOut = &n
	return res, nil
}

// ── Linux ────────────────────────────────────────────────────────────────────

type linuxGroup struct {
	run  Runner
	self string
}

// groupMembers returns a group's member list, or ok=false when it doesn't
// exist.
func (g *linuxGroup) groupMembers(ctx context.Context, name string) ([]string, bool) {
	out, err := g.run(ctx, "getent", []string{"group", name}, nil)
	if err != nil {
		return nil, false
	}
	line := strings.TrimSpace(out)
	i := strings.LastIndexByte(line, ':')
	if i < 0 {
		return nil, false
	}
	var members []string
	for _, u := range strings.Split(line[i+1:], ",") {
		if u = strings.TrimSpace(u); u != "" {
			members = append(members, u)
		}
	}
	return members, true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (g *linuxGroup) IsMember(ctx context.Context, r Request) (bool, error) {
	m, err := unixName(r.Member)
	if err != nil {
		return false, err
	}
	for _, grp := range []string{"sudo", "wheel", "admin"} {
		if members, ok := g.groupMembers(ctx, grp); ok && contains(members, m) {
			return true, nil
		}
	}
	return false, nil
}

func (g *linuxGroup) Add(ctx context.Context, r Request) (Outcome, error) {
	m, err := unixName(r.Member)
	if err != nil {
		return Outcome{}, err
	}
	if _, err := g.run(ctx, "id", []string{m}, nil); err != nil {
		return Outcome{}, fmt.Errorf("no account %s on this machine", m)
	}
	grp := ""
	var members []string
	for _, name := range []string{"sudo", "wheel"} {
		if ms, ok := g.groupMembers(ctx, name); ok {
			grp, members = name, ms
			break
		}
	}
	if grp == "" {
		return Outcome{}, fmt.Errorf("neither a sudo nor a wheel group exists")
	}
	// the script asks id -nG, which also counts a primary group
	if contains(members, m) || g.inGroupByID(ctx, m, grp) {
		return Outcome{Success: true, State: StateAlready, Member: m, Group: grp}, nil
	}
	if _, err := g.run(ctx, "gpasswd", []string{"-a", m, grp}, nil); err != nil {
		return Outcome{}, fmt.Errorf("gpasswd couldn't add %s to %s: %w", m, grp, err)
	}
	return Outcome{Success: true, State: StateAdded, Member: m, Group: grp}, nil
}

func (g *linuxGroup) inGroupByID(ctx context.Context, m, grp string) bool {
	out, err := g.run(ctx, "id", []string{"-nG", m}, nil)
	return err == nil && contains(strings.Fields(out), grp)
}

func (g *linuxGroup) Remove(ctx context.Context, r Request) (Outcome, error) {
	m, err := unixName(r.Member)
	if err != nil {
		return Outcome{}, err
	}
	switch {
	case m == "root":
		return Outcome{}, ErrRoot
	case g.self != "" && m == g.self:
		return Outcome{}, ErrOwnAccount
	}
	var in []string
	others := 0
	for _, grp := range []string{"sudo", "wheel", "admin"} {
		members, ok := g.groupMembers(ctx, grp)
		if !ok {
			continue
		}
		for _, u := range members {
			switch {
			case u == m:
				in = append(in, grp)
			case u != "root":
				others++
			}
		}
	}
	if len(in) == 0 {
		return Outcome{Success: true, State: StateAbsent, Member: m}, nil
	}
	if others == 0 {
		return Outcome{}, lastAdminError(m)
	}
	for _, grp := range in {
		if _, err := g.run(ctx, "gpasswd", []string{"-d", m, grp}, nil); err != nil {
			return Outcome{}, fmt.Errorf("gpasswd couldn't remove %s from %s: %w", m, grp, err)
		}
	}
	res := Outcome{Success: true, State: StateRemoved, Member: m}
	n := 0
	if r.SignOut {
		if _, err := g.run(ctx, "loginctl", []string{"terminate-user", m}, nil); err == nil {
			n = 1
		}
	}
	res.SignedOut = &n
	return res, nil
}
