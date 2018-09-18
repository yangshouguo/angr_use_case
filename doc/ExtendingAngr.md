# Extending Angr

## 1. Hooks and SimProcedures in Detail

### 1.1 Quick Start

```python
>>> from angr import Project, SimProcedure
>>> project = Project('examples/fauxware/fauxware')

>>> class BugFree(SimProcedure):
...    def run(self, argc, argv):
...        print 'Program running with argc=%s and argv=%s' % (argc, argv)
...        return 0

# this assumes we have symbols for the binary
>>> project.hook_symbol('main', BugFree())

# Run a quick execution!
>>> simgr = project.factory.simulation_manager()
>>> simgr.run()  # step until no more active states
Program running with argc=<SAO <BV64 0x0>> and argv=<SAO <BV64 0x7fffffffffeffa0>>
<SimulationManager with 1 deadended>  # <SAO <BV64 0x0>>是一个SimActionObject类，是对普通bitvector的简单包装，它可以跟踪SimProcedure中用它做什么，有助于静态分析。
```

`SimProcedure`运行时将通过调用约定自动从程序状态中提取参数，并使用它们调用`run`函数。类似地，当从run函数返回一个值时，它将被置于该状态（同样，根据调用约定），并执行从函数返回的实际控制流动作，这取决于体系结构可能涉及跳转到链接寄存器或跳转到堆栈弹出的结果 。

SimProcedure旨在完全取代被hook的函数。实际上，SimProcedures的原始用例正在取代库函数。

### 1.2 Implementation Context

在`Project`类中，`project._sim_procedures`字典是从地址到`SimProcedure`实例的映射。当执行管道（execution pipeline）到达该字典中存在的地址，即挂钩的地址时，它将执行`project._sim_procedures [address] .execute(state)`。参考调用约定来提取参数，创建自身的副本以保持线程安全，并运行`run()`方法。每次运行`SimProcedure`时都必须生成一个新的`SimProcedure`实例，因为运行`SimProcedure`的过程必然涉及在`SimProcedure`实例上改变状态，因此需要为每个步骤分别设置，以免遇到竞争条件多线程环境 。

#### kwargs

在多个地方hook相同的`SimProcedure`，但每次稍有不同： 传递给`SimProcedure`构造函数的任何其他关键字参数最终将作为关键字`args`传递给`SimProcedure`的`run()`方法。

### 1.3 Data Types

`run()`方法根据调用约定自动获取参数`<SAO <BV64 0xSTUFF>> `是`SimActionObject`， 直接返回返回了`python int 0`，自动升级为字大小的位向量。（可以返回原生数字、位向量或`SimActionObject`）。 ？？？？

编写处理浮点数的过程，需要手动指定调用约定。 只需为钩子提供一个`cc`：`cc = project.factory.cc_from_arg_kinds((True，True), ret_fp=True)`和`project.hook(address, ProcedureClass(cc=mycc))`。这个传入调用约定的方法适用于所有调用约定，因此如果angr的自动检测不正确，可以手动修复。 ？？？？

### 1.4 Control Flow

退出SimProcedure：从`run()`返回一个值。这实际上是调用`self.ret(value)`的简写。 `self.ret()`是一个知道如何执行从函数返回的特定操作的函数。 

SimProcedures可以使用许多不同的函数，例如：

- `ret(expr)`: 返回一个函数；
- `jump(addr)`: 跳转到二进制文件中的一个地址；
- `exit(code)`: 终止程序；
- `call(addr, args, continue_at)`: 调用二进制文件中的一个函数；
- `inline_call(procedure, *args)`: 调用（in-line方式？？？？）另一个SimProcedure并返回结果 

`call(addr, args, continue_at)`值得关注。

#### 1.4.1 Conditional Exits

从SimProcedure中添加条件分支：直接使用SimSuccessors对象进行当前执行步骤（the current execution step）。 

接口是`self.successors.add_successor(state, addr, guard, jumpkind)`。请记住，传入的状态不会被复制并且会被变异，请务必事先创建副本！ 

#### 1.4.2 SimProcedure Continuations

调用二进制函数并在SimProcedure中执行恢复：“SimProcedure Continuation”。使用`self.call(addr, args, continue_at)`时，`addr`要调用的地址，`args`是要调用它的参数的元组，而`continue_at`是另一个方法（在`SimProcedure`类中。希望该调用返回后继续执行的方法。）的名字。此方法必须与`run()`方法具有相同的签名。此外，可以传递关键字参数`cc`作为与被调用者通信的调用约定。 ？？？？

执行此操作时，将完成当前步骤（current step），然后在指定的函数重新开始执行下一步（next step）。当该函数返回时，它必须返回到某个具体地址。该地址由`SimProcedure`运行时指定：地址在`angr`的`externs`段中分配，用作返回给定方法调用的返回站点（return site）。然后它被一个过程实例的副本挂钩，该`procedure instance`被调整来运行指定的`continue_at`函数而不是`run()`，第一次使用相同的`args`和`kwargs`。？？？？

 为了正确使用扩展子系统，需要将两个元数据附加到SimProcedure类： 

- 设置类变量 `IS_FUNCTION = True`
- 将类变量`local_vars`设置为字符串元组，其中每个字符串是`SimProcedure`上的实例变量的名称，希望在返回时保留该变量的值。局部变量可以是任何类型，只要不改变它们的实例即可。 

存在某种辅助存储保留所有这些数据。状态插件`state.callstack`有一个名为`.procedure_data`的条目，`SimProcedure`运行时使用该条目存储当前调用帧的本地信息。 `angr`跟踪堆栈指针，以使`state.callstack`的当前顶部成为有意义的本地数据存储。它应该存储在堆栈帧的内存中，但是数据不能被序列化和/或内存分配很难。 ？？？？

```python
class LinuxLoader(angr.SimProcedure):
    NO_RET = True
    IS_FUNCTION = True
    local_vars = ('initializers',)

    def run(self):
        self.initializers = self.project.loader.initializers
        self.run_initializer()

    def run_initializer(self):
        if len(self.initializers) == 0:
            self.project._simos.set_entry_register_values(self.state)
            self.jump(self.project.entry)
        else:
            addr = self.initializers[0]
            self.initializers = self.initializers[1:]
            self.call(addr, (self.state.posix.argc, self.state.posix.argv, self.state.posix.environ), 'run_initializer')
```

这是`SimProcedure`扩展巧妙的用法。首先，请注意当前project可用于过程实例（procedure instance）。这为了安全起见，通常只希望将project用作只读或仅附加数据结构。这里只是从加载器中获取动态初始化器列表。然后，只要列表不为空，就会从列表中弹出单个函数指针（注意不要改变列表，因为列表对象是跨状态共享的），然后调用它，再次返回`run_initializer函数`。当运行完初始化器时，设置进入状态（entry state）并跳转到程序入口点。 

### 1.5 Global Variables、

简而言之，可以将全局变量存储在`state.globals`中。这是一个字典，只是从状态到后继状态（successor state）的浅层复制。因为它只是一个浅表副本，所以它的成员是相同的实例，所以适用与`SimProcedure continuation`中的局部变量相同的规则。需要注意**不要改变任何用作全局变量的项**。 

### 1.6 Helping out static analysis

类变量`IS_FUNCTION`，它允许使用`SimProcedure`扩展。可以设置更多的类变量，尽管这些变量没有直接的好处 —— 它们只是标记函数的属性，以便静态分析知道它在做什么。

- `NO_RET`：如果控制流永远不会从此函数返回，则将此项设置为true 
- `ADDS_EXITS`：如果执行除返回之外的任何控制流，将此设置为true 
- `IS_SYSCALL`：是否是系统调用

此外，如果设置`ADDS_EXITS`，可能还需要定义方法`static_exits()`。此函数接受一个参数，一个将在函数启动时执行的IRSB列表，并返回一个列表，列出在这种情况下函数将生成的所有出口。返回值应该是`(address(int), jumpkind(str))`的元组列表。这是一个快速，尽力而为的分析。 ？？？？

### 1.7 User Hooks

编写和使用SimProcedure的过程会产生很多假设（要hook整个函数）。`user hook`可以简化hook代码段的过程。 

```python
>>> @project.hook(0x1234, length=5)
... def set_rax(state):
...     state.regs.rax = 1
```

使用单个函数而不是整个`SimProcedure`子类。不执行参数提取，不会产生复杂的控制流。 

控制流由长度参数控制。在此示例中函数完成执行后，下一步将在hook地址后的5个字节处开始。如果省略length参数或将其设置为零，则执行将在完全hook的地址处继续执行二进制代码，而不重新触发挂钩。 `Ijk_NoHook `jumpkind允许这种情况发生。

 如果想要更多地控制来自user hook的控制流，可以返回一个后继状态列表。每个后继者都应该有`state.regs.ip`，`state.scratch.guard`和`state.scratch.jumpkind set`。 `ip`是目标指令指针，`guard`是一个符号布尔值，表示添加到与其他相关的状态相对于其他状态的约束，而jumpkind是一个VEX枚举字符串，如`Ijk_Boring`，表示分支性质。？？？？

 一般规则是，如果希望SimProcedure能够提取函数参数或导致程序返回，则编写一个完整的SimProcedure类。否则，使用用户挂钩（user hook）。 

### 1.8 Hooking Symbols

动态链接的程序有一个符号列表，必须从它们列为依赖项的库中导入，而angr将确保每个导入符号都可以通过以下方式解决：一些地址，无论是函数的真正实现，还是只是一个无用stub的虚拟地址。因此，可以使用`Project.hook_symbol` API来挂钩符号引用的地址。？？？？

这意味着可以使用自己的代码替换库函数。例如，要使用始终返回一个值的持续序列的函数替换`rand()`：

 ```python
>>> class NotVeryRand(SimProcedure):
...     def run(self, return_values=None):
...         rand_idx = self.state.globals.get('rand_idx', 0) % len(return_values)
...         out = return_values[rand_idx]
...         self.state.globals['rand_idx'] = rand_idx + 1
...         return out

>>> project.hook_symbol('rand', NotVeryRand(return_values=[413, 612, 1025, 1111]))
# 每当程序试图调用rand()时，会循环返回return_values数组中的整数。
 ```

## 2. Writing State Plugins

