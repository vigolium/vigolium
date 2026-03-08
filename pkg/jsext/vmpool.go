package jsext

import (
	"sync"

	"github.com/grafana/sobek"
	"go.uber.org/zap"
)

// VMPool pre-compiles a JS script and reuses sobek.Runtime instances via sync.Pool.
// Each Get() returns a ready-to-use VM with API bindings and the script already executed.
type VMPool struct {
	program *sobek.Program
	opts    APIOptions
	pool    sync.Pool
}

// NewVMPool pre-compiles the script source and creates a pool of ready VMs.
// Returns an error if the script fails to compile.
func NewVMPool(script *LoadedScript, opts APIOptions) (*VMPool, error) {
	prog, err := sobek.Compile(script.Path, script.Source, false)
	if err != nil {
		return nil, err
	}

	p := &VMPool{
		program: prog,
		opts:    opts,
	}
	p.pool.New = func() any {
		return p.createVM()
	}
	return p, nil
}

// Get returns a ready-to-use VM from the pool.
func (p *VMPool) Get() *sobek.Runtime {
	return p.pool.Get().(*sobek.Runtime)
}

// Put returns a VM to the pool for reuse.
func (p *VMPool) Put(vm *sobek.Runtime) {
	p.pool.Put(vm)
}

func (p *VMPool) createVM() *sobek.Runtime {
	vm := sobek.New()

	// Set up module.exports
	exports := vm.NewObject()
	module := vm.NewObject()
	_ = module.Set("exports", exports)
	_ = vm.Set("module", module)
	_ = vm.Set("exports", exports)

	// Set up API
	SetupAPI(vm, p.opts)

	// Run the pre-compiled program
	if _, err := vm.RunProgram(p.program); err != nil {
		zap.L().Error("Failed to execute JS script (pre-compiled)",
			zap.Error(err))
	}

	return vm
}
