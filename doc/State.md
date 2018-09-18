# Machine State - memory, registers, and so on

## reading and writing memory and registers

`state.regs`提供对当前状态的寄存器的读写权限，通过每个寄存器的名字来标识

`state.mem`提供对内存的读写接口，通过内存地址来标识

下面是对状态数据读写的例子：

	>>> import angr, claripy
	>>> proj = angr.Project('/bin/true')
	>>> state = proj.factory.entry_state()
	# copy rsp to rbp
	>>> state.regs.rbp = state.regs.rsp
	# store rdx to memory at 0x1000
	>>> state.mem[0x1000].uint64_t = state.regs.rdx
	# dereference rbp
	>>> state.regs.rbp = state.mem[state.regs.rbp].uint64_t.resolved
	# add rax, qword ptr [rsp + 8]
	>>> state.regs.rax += state.mem[state.regs.rsp + 8].uint64_t.resolved

## Basic Execution
主要是介绍Simulation Manager的作用

一个很简单的接口就是 `state.step()`,这个接口会执行一步符号执行，返回一个对象叫做 *SimSuccessors*. 不像正常的执行过程，符号执行可能会产生多个后继状态。现在我们关注`.successor`属性，这是一个列表，包含所有的后继状态。


例如运行遇到分支条件 `if (x > 4) `时，angr会生成两个路径，对应两个状态，其中一个状态中对应约束条件 `<Bool x_32_1 > 4>`,另一个对应的状态的约束条件 `<Bool x_32_1 < 4>`

下面是一个例子：

	>>> proj = angr.Project('examples/fauxware/fauxware')
	>>> state = proj.factory.entry_state(stdin=angr.SimFile) # ignore that argument for n
	ow - we're disabling a more complicated default setup for the sake of education
	>>> while True:
	... succ = state.step()
	... if len(succ.successors) == 2:
	... break
	... state = succ.successors[0]
	>>> state1, state2 = succ.successors
	>>> state1
	<SimState @ 0x400629>
	>>> state2
	<SimState @ 0x400699

## State Presets
如何创建一个程序状态State？例如`project.factory.entry_state()`

所有方式如下

1. .blank_state() : 创建一个空白的程序状态，该状态下大部分数据都没有被初始化（都是符号值）

2. .entry_state() : 创建一个状态来执行主二进制文件的入口代码

3. .full_init_state() : 创建一个状态来执行所有主二进制文件入口代码之前的准备工作。例如共享库构建或者预初始化。结束之后跳转到程序主入口

4. .call_state() 创建一个状态来执行给定的函数

你可以通过如下参数自定义程序状态（对以上函数都适用）

* 所有以上函数都必须有 *addr* 参数
* 如果被执行的程序或者执行环境可以接受命令行参数，那么你可以通过 *args*和环境变量的一个字典类型的参数*env*，传递给 *entry_state*和*full_init_state*.
参数可以是字符串也可以是 `bitvectors`。默认 *arg*是空列表。

* 如果你希望*argc*是符号值，那你可以传递一个符号的位向量给*argc*给*entry_state*和*full_init_state*. 但是注意，要添加约束使得*argc*不能大于*args*的参数个数。

* 如果使用 *.call_state(addr, arg1, arg2, ...)*,参数可以是python数据类型中的 *integer* *string* *array* 或者符号值 *bitvector*。 如果你想传一个内存地址的指针作为参数，你需要用到 *angr.PointerWrapper("point to me!")*

* 如果想指定函数的调用约定（例如fast_call）,你可以通过*cc*参数传递一个 **SimCC**实例


## Low level interface for memory

* state.mem 接口
你可以用 `state.memory` 的方法： `.load(addr, size)` 和 `.store(addr, val)`

	>>> s = proj.factory.blank_state()
	>>> s.memory.store(0x4000, s.solver.BVV(0x0123456789abcdef0123456789abcdef, 128))
	>>> s.memory.load(0x4004, 6) # load-size is in bytes
	<BV48 0x89abcdef0123>

