package commands

import (
	"sync"

	"github.com/The-17/agentsecrets/pkg/agents"
	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/projects"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/The-17/agentsecrets/pkg/workspaces"
)

// App is the single owner of the CLI's shared, network-backed services. Before
// this existed, each service lived in its own package-level global initialized
// eagerly in init(), which built an authenticated API client (and a second,
// throwaway auth.Service inside NewAuthenticatedClient) on every invocation —
// even `--version` and `--help`. App collapses those globals into one struct and
// builds them lazily on first use, so metadata-only and machine paths pay
// nothing for services they never touch.
//
// Construction is guarded by sync.Once: the first accessor call wires the whole
// graph off a single API client; subsequent calls return the cached services.
// Commands reach services through the accessor methods (app.Auth(), app.Agents(),
// …) rather than the fields directly, which is what triggers lazy construction.
type App struct {
	once sync.Once

	api        *api.Client
	auth       *auth.Service
	workspaces *workspaces.Service
	projects   *projects.Service
	secrets    *secrets.Service
	agents     *agents.Service
}

// app is the process-wide App. It is declared here and left zero-valued; the
// first accessor call constructs the services. Nothing in init() forces this,
// so `agentsecrets --version` never builds an API client.
var app = &App{}

// ensure builds the service graph exactly once. All accessors funnel through it.
func (a *App) ensure() {
	a.once.Do(func() {
		// A single authenticated client backs every service. NewAuthenticatedClient
		// wires the token-refresh callback using one internal auth.Service; we reuse
		// that same client here rather than constructing a second one.
		a.api = auth.NewAuthenticatedClient()
		a.auth = auth.NewService(a.api)
		a.workspaces = workspaces.NewService(a.api)
		a.projects = projects.NewService(a.api)
		a.secrets = secrets.NewService(a.api)
		a.agents = agents.NewService(a.api)
	})
}

// API returns the shared authenticated API client, constructing the service
// graph on first use.
func (a *App) API() *api.Client {
	a.ensure()
	return a.api
}

// Auth returns the shared auth service.
func (a *App) Auth() *auth.Service {
	a.ensure()
	return a.auth
}

// Workspaces returns the shared workspaces service.
func (a *App) Workspaces() *workspaces.Service {
	a.ensure()
	return a.workspaces
}

// Projects returns the shared projects service.
func (a *App) Projects() *projects.Service {
	a.ensure()
	return a.projects
}

// Secrets returns the shared secrets service.
func (a *App) Secrets() *secrets.Service {
	a.ensure()
	return a.secrets
}

// Agents returns the shared agents service.
func (a *App) Agents() *agents.Service {
	a.ensure()
	return a.agents
}
