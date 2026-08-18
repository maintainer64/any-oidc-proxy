package zabbix

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"any-oidc-proxy/pkg/backend"
)

type zabbixState struct {
	roles      map[string]string // name -> roleid
	groups     map[string]string // name -> groupid
	userIDs    map[string]string // username -> userid
	passwords  map[string]string // userid -> password
	nextID     int
	failCreate bool
	updates    []map[string]any
	creates    []map[string]any
}

func newZabbixState() *zabbixState {
	return &zabbixState{
		roles:     map[string]string{},
		groups:    map[string]string{},
		userIDs:   map[string]string{},
		passwords: map[string]string{},
		nextID:    1,
	}
}

// jsonRPC mock: разбирает JSON-RPC-запрос и отвечает согласно состоянию.
func (z *zabbixState) jsonRPCHandler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php" {
			z.indexHandler(t).ServeHTTP(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer zabbix-token" {
			t.Errorf("bad authorization header %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode rpc request: %v", err)
		}
		var params map[string]any
		json.Unmarshal(req.Params, &params)

		switch req.Method {
		case "role.get":
			name, _ := params["filter"].(map[string]any)["name"].(string)
			if id, ok := z.roles[name]; ok {
				json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{"roleid": id}}, "id": 1})
			} else {
				json.NewEncoder(w).Encode(map[string]any{"result": []any{}, "id": 1})
			}
		case "role.create":
			name, _ := params["name"].(string)
			id := z.nextID
			z.nextID++
			z.roles[name] = "role" + string(rune('0'+id))
			z.creates = append(z.creates, params)
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"roleids": []any{}}, "id": 1})
		case "usergroup.get":
			name, _ := params["filter"].(map[string]any)["name"].(string)
			if id, ok := z.groups[name]; ok {
				json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{"usrgrpid": id}}, "id": 1})
			} else {
				json.NewEncoder(w).Encode(map[string]any{"result": []any{}, "id": 1})
			}
		case "usergroup.create":
			name, _ := params["name"].(string)
			id := z.nextID
			z.nextID++
			z.groups[name] = "grp" + string(rune('0'+id))
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"usrgrpids": []any{}}, "id": 1})
		case "user.get":
			username, _ := params["filter"].(map[string]any)["username"].(string)
			if _, ok := z.userIDs[username]; ok {
				json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{"userid": z.userIDs[username]}}, "id": 1})
			} else {
				json.NewEncoder(w).Encode(map[string]any{"result": []any{}, "id": 1})
			}
		case "user.create":
			if z.failCreate {
				json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": -32602, "message": "user exists"}, "id": 1})
				return
			}
			username, _ := params["username"].(string)
			passwd, _ := params["passwd"].(string)
			z.userIDs[username] = "user1"
			z.passwords["user1"] = passwd
			z.creates = append(z.creates, params)
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"userids": []any{"user1"}}, "id": 1})
		case "user.update":
			z.updates = append(z.updates, params)
			passwd, _ := params["passwd"].(string)
			z.passwords["user1"] = passwd
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"userids": []any{"user1"}}, "id": 1})
		default:
			t.Errorf("unexpected rpc method %q", req.Method)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func (z *zabbixState) indexHandler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		name, password := r.FormValue("name"), r.FormValue("password")
		if uid, ok := z.userIDs[name]; ok && z.passwords[uid] == password {
			w.Header().Add("Set-Cookie", "zbx_session=sess-123; Path=/; HttpOnly")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
}

func newZabbixBackend(t *testing.T, state *zabbixState) (*OIDC, *httptest.Server) {
	rpcSrv := httptest.NewServer(state.jsonRPCHandler(t))
	t.Cleanup(rpcSrv.Close)
	return &OIDC{
		baseURL: rpcSrv.URL,
		client:  NewZabbixClientRPC(rpcSrv.URL, "zabbix-token"),
	}, rpcSrv
}

func TestZabbixLoginNewUser(t *testing.T) {
	state := newZabbixState()
	b, _ := newZabbixBackend(t, state)

	redirect, err := b.Login(context.Background(), "alice@gubanov.site", backend.UserData{
		Email: "alice@gubanov.site", Name: "Alice", Groups: []string{"devs"},
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if len(redirect.Cookies) != 1 || redirect.Cookies[0] != "zbx_session=sess-123; Path=/; HttpOnly" {
		t.Errorf("cookies = %v", redirect.Cookies)
	}
	// Роль создана под именем <группа>::oidc, группа oidc, юзер создан
	if state.roles["devs::oidc"] == "" {
		t.Error("role devs::oidc not created")
	}
	if state.groups["oidc"] == "" {
		t.Error("group oidc not created")
	}
	if _, ok := state.userIDs["alice@gubanov.site"]; !ok {
		t.Error("user not created")
	}
	// user.update передан с ролью и группой
	if len(state.updates) != 1 {
		t.Fatalf("expected 1 user.update, got %d", len(state.updates))
	}
	upd := state.updates[0]
	roleID, _ := upd["roleid"].(string)
	grp := upd["usrgrps"].([]any)[0].(map[string]any)["usrgrpid"].(string)
	if roleID == "" || grp == "" {
		t.Errorf("update params = %v", upd)
	}
	if upd["autologout"] != "15m" {
		t.Errorf("autologout = %v", upd["autologout"])
	}
}

func TestZabbixLoginExistingUser(t *testing.T) {
	state := newZabbixState()
	state.roles["default::oidc"] = "role5"
	state.groups["oidc"] = "grp9"
	state.userIDs["bob@gubanov.site"] = "user1"
	state.passwords["user1"] = "oldpass"
	b, _ := newZabbixBackend(t, state)

	redirect, err := b.Login(context.Background(), "bob@gubanov.site", backend.UserData{
		Email: "bob@gubanov.site", Name: "Bob", Groups: nil,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if len(redirect.Cookies) != 1 {
		t.Errorf("cookies = %v", redirect.Cookies)
	}
	if len(state.creates) != 0 {
		t.Errorf("expected no creates, got %v", state.creates)
	}
	// Пароль обновлён и с ним выполнен вход
	if state.passwords["user1"] == "oldpass" {
		t.Error("password not updated")
	}
}

func TestZabbixLoginRPCError(t *testing.T) {
	state := newZabbixState()
	b, rpcSrv := newZabbixBackend(t, state)
	rpcSrv.Close()

	_, err := b.Login(context.Background(), "alice@gubanov.site", backend.UserData{Email: "alice@gubanov.site"})
	if err == nil {
		t.Fatal("expected error when RPC unavailable")
	}
}

func TestZabbixLoginUserCreateFails(t *testing.T) {
	state := newZabbixState()
	state.failCreate = true
	b, _ := newZabbixBackend(t, state)

	_, err := b.Login(context.Background(), "nobody@gubanov.site", backend.UserData{Email: "nobody@gubanov.site"})
	if err == nil {
		t.Fatal("expected error when user.create fails")
	}
}

func TestZabbixClientUserLogin(t *testing.T) {
	state := newZabbixState()
	state.userIDs["alice@gubanov.site"] = "user1"
	state.passwords["user1"] = "pw"
	srv := httptest.NewServer(state.indexHandler(t))
	t.Cleanup(srv.Close)
	c := &ZabbixClientRPC{urlLogin: srv.URL + "/index.php"}

	cookies, err := c.UserLogin(context.Background(), "alice@gubanov.site", "pw")
	if err != nil {
		t.Fatalf("UserLogin: %v", err)
	}
	if len(cookies) != 1 || cookies[0] != "zbx_session=sess-123; Path=/; HttpOnly" {
		t.Errorf("cookies = %v", cookies)
	}
}

func TestZabbixClientUserLoginWrongPassword(t *testing.T) {
	state := newZabbixState()
	state.userIDs["alice@gubanov.site"] = "user1"
	state.passwords["user1"] = "pw"
	srv := httptest.NewServer(state.indexHandler(t))
	t.Cleanup(srv.Close)
	c := &ZabbixClientRPC{urlLogin: srv.URL + "/index.php"}

	cookies, err := c.UserLogin(context.Background(), "alice@gubanov.site", "wrong")
	if err != nil {
		t.Fatalf("UserLogin: %v", err)
	}
	if len(cookies) != 0 {
		t.Errorf("expected no cookies for wrong password, got %v", cookies)
	}
}

func TestZabbixProvisionUser(t *testing.T) {
	b := &OIDC{client: NewZabbixClientRPC("http://localhost:1", "tok")}
	id, err := b.ProvisionUser(context.Background(), backend.UserData{Email: "x@gubanov.site"})
	if err != nil {
		t.Fatalf("ProvisionUser: %v", err)
	}
	if id != "x@gubanov.site" {
		t.Errorf("id = %q", id)
	}
}
