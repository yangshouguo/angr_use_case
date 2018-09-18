## 1. Gotchas

## 2. Whole Pipeline

### 2.1 Simulation Managers

#### 2.1.1 `step()`

`SimulationManager.step()`函数有多个可选参数。其中最重要的是`stash`，`n`，`until`和`step_func`。`n`最常用 —— `step()`函数循环调用`_one_step()`函数并传递其所有参数，直到完成n个循环或发生其他终止条件。如果未提供n，则默认为1，（除非提供了`unti`l参数，循环上将没有数字上限）。

但是，在检查任何终止条件之前，会应用`step_func` - 此函数接受当前`manager`并返回一个新`manager`来替换它。在编写一个`step function`时，参考（大多数常见的`manager functions`也会返回一个`manager`）。 —— 如果`manager`是不可变的（构造函数中的`immutable = True`），那么这是一个新对象，但是否则它与之前的对象是同一个。？？？？

现在，检查终止条件 -——正在操作的`stash`（默认情况下为“active”）已经为空，或者`until`回调函数返回`True`。如果这些条件都不满足，循环回来再次调用`_one_step()`。

注意，如果使用`.run()`，则会自动提供`until`回调函数作为所有附加的探索技术（exploration techniques）的`complete()`回调函数的总和（sum）。默认情况下，“sum”是`any`function，但可以通过设置`simgr.completion_mode`来更改（例如，更改为·`all`）。？？？？ 

#### 2.1.2 `_one_step()`

该函数会调用重写了`step`函数的`exploration technique`。这些`exploration technique`的效果可以结合。实现了`step`函数的`exploration technique`会接受一个manager并返回一个新的manager（这个新的manager会向前执行一步，并应用`exploration technique`的作用）。这需要`exploration technique`自己包含`execution`，需要通过再次调用manager上的`_one_step()`来实现。然后，对该函数的调用循环重新开始，当进程到达`_one_step()`时，当前的`exploration technique`会从`step`回调函数列表中弹出。然后，如果有更多的`exploration technique`提供了`step`回调函数，则调用下一个，递归直到这个列表变空。从回调函数返回后，`_one_step`会将回调函数压到回调堆栈，然后返回。 ？？？？

 提供`step`回调函数的`exploration technique`如下：？？？？

- 最终用户调用`step()`
- `step()`调用`_one_step()`
- `_one_step()`从活动（active）的`step` `exploration technique`回调列表中弹出单个`exploration technique`，并使用当前正在操作的manager调用它。 
- 这个回调函数调用它被调用的manager上的`_one_step()`
- 重复此过程，直到不再有回调为止 

一旦没有更多的`step`回调函数，或者如果从未进行过`step`回调，将回退到默认的`stepping procedure`。这涉及一个原本可以传递给`SimulationManager.step()`  ——`selector_func`的参数。如果它存在，那么它用于过滤将实际操作的`working stash`中的状态。对于这些状态，调用`SimluationManager._one_state_step()`，再次传递所有尚未使用的参数。 `_one_state_step()`将返回一个列表的`dict`，该列表对`stepping`该状态的`successors`进行分类。效用函数`SimulationManager._record_step_results()`将对这些列表进行操作，以迭代方式构建新的`stash`集合，manager在完成所有这些操作时将包含这个`stash`集合，并应用`exploration technique`可提供的`filter`回调函数。？？？？ 

#### 2.1.3 `_one_state_step()`

首先，我们需要应用`step_state` `exploration technique` hooks 。这些钩子不像`step`回调那样嵌套 —— 只能应用一个钩子，其余的只在失败的情况下使用。如果任何`step_state` hook成功，则立即从`_one_state_step()`返回结果。对`filter`回调的要求是返回`_one_state_step()`应该返回的列表组成的同一个dict！如果所有这些都失败了，或者从来没有开始，我们再次回到默认程序。 

首先，我们向前推进`state`。如果提供了`successor_func`作为`step()`的参数，则使用它 ——希望它将返回一个`SimSuccessors`对象，其中包含所有适当的分类（正常，无约束，不可满足等）。如果未提供此参数，使用`project.factory.successors`方法向前推进状态并获取的`SimSuccessors`。然后将所有这些都放入具有适当`stash`名称的`state`列表组成的字典中。 

整个过程在`try-except`块中完成，该块将捕获任何错误并将原始状态（state）作为`ErrorRecord`对象的一部分放入“errored”列表中。 

### 2.2 Engine Selection

`SimEngine`知道如何获取状态（state）并生成其后继者（successors） 。每个`project`在它的`factory`中都有一个`engines`列表，而`project.factory.successors`的默认行为是按顺序尝试所有engine，并获取第一个有效的engined的结果。有几种方法可以改变这种行为：

- 如果传递参数`default_engine = True`，则唯一要尝试的引擎是最后的默认引擎，通常是`SimEngineVEX`。 
- 如果给参数`engines`传递了一个列表，则将使用这个列表而不是默认的engines列表 。

这两个参数都可以在顶部提供，传递给`.step()`,` explore()`,`.run()`或其他，开始execution，并且它们将被过滤到此级别。？？？？任何其他参数将继续传递下来，直到它们到达它们所针对的引擎。引擎将丢弃它不理解的任何参数。 

engines的默认列表：

- `SimEngineFailure`
- `SimEngineSyscall`
- `SimEngineHook`
- `SimEngineUnicorn`
- `SimEngineVEX`

每个引擎都有一个`check()`方法，可以快速确定它是否适合使用。如果`check()`通过，则`process9)`将用于实际生成`successors`。即使`check()`通过，`process()`也可能失败，会返回一个将`.processed`属性设置为`False`的`SimSuccessors`对象。这两种方法都接收所有剩余的`step`参数。有用的参数是`addr`和`jumpkind`，通常用来覆盖`state`提取的信息。？？？？

最后，一旦引擎处理了一个状态，就会对结果进行简单的后处理，以便在系统调用的情况下修复指令指针。如果execution以匹配`Ijk_Sys*`的`jumpkind`结束，则调用`SimOS`以检索当前系统调用的地址，并将结果状态（state）的指令指针更改为该地址。原始地址存储在名为`ip_at_syscall`的状态寄存器中。这对于纯执行（pure execution）不是必需的，但在静态分析中，有助于使系统调用与普通代码位于不同的地址。 

### 2.3 Engines

`SimEngineFailure`处理错误情况。它仅在前一个`jumpkind`是`Ijk_EmFail`，`Ijk_MapFail`，`Ijk_Sig *`，`Ijk_NoDecode`（但仅限于未hook的地址）或`Ijk_Exit`之一时使用。在前四种`jumpkind`中，其动作是抛出一个异常。在最后一种情况下，它的动作是不产生successors。

`SimEngineSyscall`用于系统调用。当前一个`jumpkind`是`Ijk_Sys *`形式时使用。工作原理是调用`SimOS`来检索应该运行的`SimProcedure`来响应这个系统调用，然后运行它。

`SimEngineHook`提供`angr`中的hooking功能。当状态位于被hook的地址时，使用它，而且前一个`jumpkind`不能是`Ijk_NoHook`。它只是查找相关的`SimProcedure`并在状态下运行它。它也是参数`procedure`，将使`check`始终成功，并且将使用此过程而不是从钩子获得的`SimProcedure`，因此可以提供此参数以简单地在给定状态上执行一个过程（procedure）作为一轮执行（a round of execution）。 

请注意，`syscall`和`hook`引擎都利用了`SimEngineProcedure`引擎。这不是一个子类关系，但类似。

 `SimEngineUnicorn`使用`Unicorn Engine`执行具体执行（concrete execution）。它在启用状态选项`o.UNICORN`时使用，并且满足为实现最高效率而设计的无数其他条件（如*2.4*所述）。 

`SimEngineVEX`很庞大，无论何时，都可以使用它。它尝试将字节从当前地址提升到IRSB，然后以符号方式执行该IRSB。有大量参数可以控制这个过程。 [SimEngineVEX  API](http://angr.io/api-doc/angr.html#angr.engines.vex.engine.SimEngineVEX.process)

SimEngineVEX挖掘到IRSB的确切过程有点复杂，但基本上它按顺序运行所有块的语句。（*可以阅读源码了解angr符号执行过程*）

#### Engine instances

除了步进过程（stepping process）的参数，还可以实例化这些引擎的新版本！查看[API文档](http://angr.io/api-doc/angr.html#module-angr.engines)以了解每个引擎可以采用的选项。一旦有了新的引擎实例，您可以将其传递给步进过程（step process），或者直接将其放入`project.factory.engines`列表中以供自动使用。 

### 2.4 Unicorn Engine

如果添加`o.UNICORN`状态选项，则会在每个步骤调用`SimEngineUnicorn`，并尝试查看是否允许使用`Unicorn`进行具体执行。 

真正想要做的是在状态中添加预定义的`o.unicorn`（小写）选项集 ：

```python
unicorn = { UNICORN, UNICORN_SYM_REGS_SUPPORT, INITIALIZE_ZERO_REGISTERS, UNICORN_HANDLE_TRANSMIT_SYSCALL }
```

这些将启用一些额外的功能和默认值。此外，可以在`state.unicorn`插件上调整很多选项。

了解Unicorn如何工作的一个好方法是检查**日志**记录输出 :

```python
(logging.getLogger('angr.engines.unicorn_engine').setLevel('DEBUG'); logging.getLogger('angr.state_plugins.unicorn_engine').setLevel('DEBUG')
```

 ```python
INFO    | 2017-02-25 08:19:48,012 | angr.state_plugins.unicorn | started emulation at 0x4012f9 (1000000 steps)
 ```

在这里，angr从`0x4012f9`的基本块开始转向unicorn引擎。最大步数设置为`1000000`，因此如果执行（execution）在Unicorn中保留1000000个块，它将自动弹出。这是为了避免挂在无限循环中。块数可通过`state.unicorn.max_steps`变量进行配置。 

```python
INFO    | 2017-02-25 08:19:48,014 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
INFO    | 2017-02-25 08:19:48,016 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,019 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
INFO    | 2017-02-25 08:19:48,022 | angr.state_plugins.unicorn | mmap [0x602000, 0x602fff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,023 | angr.state_plugins.unicorn | mmap [0x400000, 0x400fff], 5
INFO    | 2017-02-25 08:19:48,025 | angr.state_plugins.unicorn | mmap [0x7000000, 0x7000fff], 5
```

当访问时，angr执行由unicorn引擎访问的数据的延迟映射（lazy mapping）。` 0x401000`是它正在执行的指令页面，`0x7fffffffffe0000`是堆栈，依此类推。其中一些页面是符号的，这意味着它们至少包含一些数据，这些数据被访问时将导致执行（execution）从Unicorn中止。 

```python
INFO    | 2017-02-25 08:19:48,037 | angr.state_plugins.unicorn | finished emulation at 0x7000080 after 3 steps: STOP_STOPPOINT
```

执行（execution）在Unicorn中保留3个基本块（计算浪费，考虑到所需的设置），之后它到达一个`simprocedure`位置并跳出来执行angr中的`simproc`。 

```python
INFO    | 2017-02-25 08:19:48,076 | angr.state_plugins.unicorn | started emulation at 0x40175d (1000000 steps)
INFO    | 2017-02-25 08:19:48,077 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
INFO    | 2017-02-25 08:19:48,079 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,081 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
```

在`simprocedure`后，execution会跳回Unicorn 

```python
WARNING | 2017-02-25 08:19:48,082 | angr.state_plugins.unicorn | fetching empty page [0x0, 0xfff]
INFO    | 2017-02-25 08:19:48,103 | angr.state_plugins.unicorn | finished emulation at 0x401777 after 1 steps: STOP_EXECNONE
```

由于二进制文件访问了零页面（Zero-Page），execution立即从Unicorn中弹出。 

```python
INFO    | 2017-02-25 08:19:48,120 | angr.engines.unicorn_engine | not enough runs since last unicorn (100)
INFO    | 2017-02-25 08:19:48,125 | angr.engines.unicorn_engine | not enough runs since last unicorn (99)
```

为了避免波动进出（不断进入弹出）Unicorn（代价昂贵），有冷却（`state.unicorn`插件的属性）等待某些条件保持（即，没有符号内存访问X块）之后跳回到unicorn时由于除了`simprocedure`或系统调用之外的任何东西都会中止unicorn运行。在这里，它正在等待的条件是在重新开始之前执行100个块。 ？？？？

## 3. Speed considerations

angr受限于python的速度，但是仍然可以优化以加快其速度。

### 3.1 General tips

- 使用[pypy](http://pypy.org/)
- 除非需要，否则不要加载共享库。 angr中的默认设置是不惜一切代价来查找与加载的二进制文件兼容的共享库，包括直接从OS库中加载它们。这可能会在很多场景中使事情复杂化。如果执行的分析比简单的符号执行（特别是控制流图形构造）更抽象，可能需要牺牲精确度来保证易处理性。当函数库调用不存在的函数时，angr会做出合理的处理。
-  使用`hooking`和`SimProcedures`。如果启用共享库，那么为正在跳入的复杂库函数编写`SimProcedures`。如果此项目没有自治要求，您通常可以隔离分析挂起的各个问题点，并用钩子汇总它们。 ？？？？（并行分析每个库函数？？？？）
- 使用`SimInspect`。 [SimInspect](https://docs.angr.io/docs/simulation.html#breakpoints)是最不充分利用的，也是angr最强大的功能之一。可以hook和修改几乎任何angr的行为，包括**内存索引方式**（这通常是angr分析中最慢的部分）。 
- 写一个具体化的策略。针对内存索引解析问题的更强大的解决方案是具体化策略（[concretization strategy](https://github.com/angr/angr/tree/master/angr/concretization_strategies))
- 使用Replacement Solver。可以使用`angr.options.REPLACEMENT_SOLVER`状态选项启用它。Replacement Solver允许指定在求解时应用的AST替换。如果添加替换项以便在执行求解时将所有符号数据替换为具体数据，则会大大减少运行时间。添加替换的API是`state.se._solver.add_replacement(old，new)`。Replacement Solver有点挑剔，所以有一些陷阱，但它肯定会有所帮助。 ？？？？
### 3.2 执行大量具体或部分具体的execution

- 使用[unicorn](https://github.com/unicorn-engine/unicorn/)引擎。angr可以利用unicorn engine进行具体仿真。在`state`的添加`angr.options.unicorn`的选项。`angr.options`下的大多数项都是独立选项，但是`angr.options.unicorn`是一个选项集合（set）。unicorn不一定适合angr使用，angr打了一些补丁。？？？？
- 启用快速内存（fast memory）和快速寄存器（fast registers）。状态选项`angr.options.FAST_MEMORY`和`angr.options.FAST_REGISTERS`将执行此操作。这将会吧memory/registers切换到一个低敏感度的内存模型，会为了速度牺牲部分准确性。 TODO：记录具体损失了那些精度。虽然大多数具体访问应该是安全的。注意：与具体化策略（concretization strategies）不兼容。 
- 提前将输入具体化。这是[driller](https://www.internetsociety.org/sites/default/files/blogs-media/driller-augmenting-fuzzing-through-selective-symbolic-execution.pdf)所采取的方法。在执行（execution）开始之前，用表示输入的符号数据填充`state.posix.files [0]`，然后将符号数据约束到我们想要的输入，然后设置具体的文件大小（`state.posix.files [0] .size = whatever`）。如果不需要跟踪来自`stdin`的数据，可以放弃符号部分，只需填写具体数据即可。如果除了标准输入之外还有其他输入源，对它们执行相同的操作即可。
- 使用*afterburner* 。使用unicorn时，如果添加`UNICORN_THRESHOLD_CONCRETIZATION`状态选项，则angr将接受阈值，之后会导致符号值具体化，因此execution会在Unicorn中花费更多时间。具体而言，存在以下阈值 ：
  - `state.se.unicorn.concretization_threshold_memory`——存储在内存中的符号变量在被强制具体化并强制进入Unicorn之前被允许从Unicorn中执行的次数。 
  - `state.se.unicorn.concretization_threshold_registers` ——存储在寄存器中的符号变量在被强制具体化并强制进入Unicorn之前被允许从Unicorn中执行的次数。 
  - `state.se.unicorn.concretization_threshold_instruction` ——任何给定指令强制执行跳出Unicorn（通过运行符号数据）的次数，然后在该指令遇到的任何符号数据被具体化以强制执行到Unicorn。？？？？
  - `state.se.unicorn.always_concretize` —— 一组（set）总会具体化以强制执行到unicorn的变量名称（实际上，内存和寄存器阈值最终导致变量被添加到此列表中） ？？？？
  - `state.se.unicorn.never_concretize` —— 一组变量名称，在任何条件下都不会被强化并强制进入Unicorn。 
  - `state.se.unicorn.concretize_at` —— 一组指令地址，数据应该被具体化并强制进入Unicorn。指令阈值导致地址被添加到该集合。 

*一旦某些东西被afterburner具体化，就会失去对该变量的追踪。状态仍然是一致的，但是会失去依赖性，因为Unicorn产生的东西只是具体的bits，没有记录它们来自哪些变量。*
## 4. Intermediate Representation

中间表示

为了能够分析和执行来自不同CPU架构的机器代码，例如MIPS，ARM和PowerPC，以及经典的x86，angr对中间表示执行大部分分析，过每个CPU指令对执行的基本操作进行结构化描述通。

在处理不同的体系结构时，VEX IR抽象出几种体系结构差异，允许对所有体系结构进行单一分析： 

- **Register names.**   不同架构寄存器的数量和名称有所不同，但现代CPU设计保持一个共性：每个CPU包含几个通用寄存器，一个用于存放堆栈指针的寄存器，一组用于存储条件标志的寄存器，等等。 IR为不同平台上的寄存器提供了一致的抽象接口。具体来说，VEX将寄存器建模为单独的存储空间，具有整数偏移（例如，AMD64的`rax`从该地址空间的地址16开始存储）。 
- **Memory access.**   不同的架构以不同的方式访问内存。例如，ARM可以在little-endian和big-endian模式下访问内存。 IR抽象出这些差异。 
- **Memory segmentation.**   某些体系结构（如x86）通过使用特殊的段寄存器来支持内存分段。 IR了解这种内存访问机制。 
- **Instruction side-effects.**   大多数指令都有副作用。例如，ARM上Thumb模式下的大多数操作都会更新条件标志，堆栈`push`/`pop`指令会更新堆栈指针。IR明确了这些副作用。 ？？？？

IR有很多选择。我们使用VEX，因为二进制代码升级到VEX得到了很好的支持。 VEX是一种与体系无关，无副作用的多种目标机器语言表示。它将机器代码抽象为一种表示，使程序分析更容易。该表示有四个主要类对象： 

- **Expressions.**   IR表达式表示计算值或常数值。这包括存储器加载，寄存器读取和算术运算的结果。 
- **Operations.**   IR运算描述了对IR表达式的修改。这包括整数运算，浮点运算，位运算等。应用于IR表达式的IR运算产生IR表达式。 
- **Temporary variables.**   VEX使用**临时变量**作为内部寄存器：IR表达式存储在临时变量中。可以使用IR表达式检索临时变量的内容。这些临时变量从`t0`开始编号。这些临时变量是强类型的（例如，“64位整数”或“32位浮点数”）。 
- **Statements.**   IR语句模拟目标机器状态的变化，例如内存存储和寄存器写入的影响。 IR声明使用IR表达式来表示它们可能需要的值。例如，内存存储器IR语句使用IR表达式作为写入的目标地址，并使用另一个IR表达式作为内容。 
- **Blocks.**   IR块是IR语句的集合，表示目标体系结构中的扩展基本块（称为“IR超级块”或“IRSB”）。一个块可以有几个出口。对于基本块中间的条件出口（conditional exits），使用特殊的*Exit IR*语句。 IR表达式用于表示块末尾的无条件退出的目标。 

VEX IR实际上在VEX存储库的libvex_ir.h文件（https://github.com/angr/vex/blob/master/pub/libvex_ir.h）中有很好的文档记录。一些IR表达式： 

| IR Expression   | Evaluated Value                                              | VEX Output Example  |
| --------------- | ------------------------------------------------------------ | ------------------- |
| Constant        | 常量值。                                                     | 0x4:I32             |
| Read Temp       | 存储在VEX临时变量中的值。                                    | RdTmp(t10)          |
| Get Register    | 存储在寄存器中的值。                                         | GET:I32(16)         |
| Load Memory     | 存储在存储器地址中的值，其地址由另一个IR表达式指定。         | LDle:I32 / LDbe:I64 |
| Operation       | 指定IR操作的结果，应用于指定的IR表达式参数。                 | Add32               |
| If-Then-Else    | 如果给定的IR表达式求值为0，则返回一个IR表达式。否则，返回另一个 | ITE                 |
| Helper Function | VEX对某些操作使用C辅助函数，例如计算某些体系结构的条件标志寄存器。这些函数返回IR表达式。 | function_name()     |

用于IR语句的常见表达式：

| IR Statement | Meaning                                                      | VEX Output Example                         |
| ------------ | ------------------------------------------------------------ | ------------------------------------------ |
| Write Temp   | 将VEX临时变量设置为给定IR表达式的值 。                       | WrTmp(t1) = (IR Expression)                |
| Put Register | 使用给定IR表达式的值更新寄存器。                             | PUT(16) = (IR Expression)                  |
| Store Memory | 使用值更新内存中的位置（以IR表达式给出），也可使用IR表达式更新。 | STle(0x1000) = (IR Expression)             |
| Exit         | 基本块中条件退出，其中跳转目标由IR表达式指定。条件由IR表达式指定。 | if (condition) goto (Boring) 0x4000A00:I32 |

ARM上的IR转换示例如下所示。在该示例中，减法操作被转换为包括5个IR语句的单个IR块，每个IR语句包含至少一个IR表达式（在现实中，IR块通常由多于一个指令组成）。 

寄存器名称被转换为GET表达式和PUT语句的数字索引。实际的减法是由块的前4个IR语句建模的，并且有最后一条语句建模的程序计数器的递增指向下一条指令（在这种情况下，位于0x59FC8）。？？？？

ARM指令：

```txt
subs R2, R2, #8
```

转换为VEX IR:

```txt
t0 = GET:I32(16)
t1 = 0x8:I32
t3 = Sub32(t0,t1)
PUT(16) = t3
PUT(68) = 0x59FC8:I32
```

可以在angr中使用一些VEX：使用一个名为PyVEX的库将VEX暴露给Python。此外，PyVEX实现了自己的pretty-print，因此它可以在PUT和GET指令中显示寄存器名称而不是寄存器偏移。 

angr可以通过`Project.factory.block`接口访问PyVEX。可以使用许多不同的表示来访问代码块的语法属性，但它们都具有分析特定字节序列的特性。通过`factory.block`构造函数，可获得一个可以轻松转换为多个不同表示形式的`Block`对象。`.vex`用于PyVEX IRSB，或`.capstone`用于Capstone块。 ？？？？

```python
>>> import angr

# load the program binary
>>> proj = angr.Project("/bin/true")

# translate the starting basic block
>>> irsb = proj.factory.block(proj.entry).vex
# and then pretty-print it
>>> irsb.pp()

# translate and pretty-print a basic block starting at an address
>>> irsb = proj.factory.block(0x401340).vex
>>> irsb.pp()

# this is the IR Expression of the jump target of the unconditional exit at the end of the basic block
>>> print irsb.next

# this is the type of the unconditional exit (e.g., a call, ret, syscall, etc)
>>> print irsb.jumpkind

# you can also pretty-print it
>>> irsb.next.pp()

# iterate through each statement and print all the statements
>>> for stmt in irsb.statements:
...     stmt.pp()

# pretty-print the IR expression representing the data, and the *type* of that IR expression written by every store statement
>>> import pyvex
>>> for stmt in irsb.statements:
...     if isinstance(stmt, pyvex.IRStmt.Store):
...         print "Data:",
...         stmt.data.pp()
...         print ""
...         print "Type:",
...         print stmt.data.result_type
...         print ""

# pretty-print the condition and jump target of every conditional exit from the basic block
>>> for stmt in irsb.statements:
...     if isinstance(stmt, pyvex.IRStmt.Exit):
...         print "Condition:",
...         stmt.guard.pp()
...         print ""
...         print "Target:",
...         stmt.dst.pp()
...         print ""

# these are the types of every temp in the IRSB
>>> print irsb.tyenv.types

# here is one way to get the type of temp 0
>>> print irsb.tyenv.types[0]
```

### 条件标志计算（x86 和 ARM）

x86和ARM CPU上最常见的指令副作用之一是更新条件标志，例如零标志，进位标志或溢出标志。计算机架构师通常将这些标志串联（每个条件标志是1位宽）放入一个特殊的寄存器（即x86上的EFLAGS / RFLAGS，ARM上的APSR / CPSR）。此特殊寄存器存储有关程序状态的重要信息，对于正确模拟CPU至关重要。 

VEX使用4个寄存器作为其“标志thunk描述符”来记录最新标志设置操作的细节。 VEX有一个计算标志的惰性策略：当一个更新标志的操作发生时，VEX不是计算标志，而是将代表该操作的代码存储到`cc_op`伪寄存器，把操作参数存储到`cc_dep1`和`cc_dep2`。然后，每当VEX需要获得实际的标志值时，它就可以根据其标志thunk描述符找出与所请求的标志相对应的一位实际上是什么。这是标志计算中的优化，因为VEX现在可以直接在IR中执行相关操作，而无需计算和更新标志的值。 ？？？？

在可以放在`cc_op`中的不同操作中，有一个特殊值0，它对应于`OP_COPY`操作。此操作应该将`cc_dep1`中的值复制到标志中。它只是意味着`cc_dep1`包含标志的值。 angr使用这个事实让我们有效地检索标志的值：每当我们要求实际标志时，angr计算它们的值，然后将它们转储回`cc_dep1`并设置`cc_op = OP_COPY`以便缓存计算。我们也可以使用此操作来允许用户写入标志：我们只需设置`cc_op = OP_COPY`来表示将新值设置为标志，然后将`cc_dep1`设置为该新值。 

## 5. Working with Data and Conventions

### 5.1 Working with types

angr有一个表示类型的系统。这些SimType可以在`angr.types`中找到 - 这些类中的任何一个的实例都代表一种类型。许多类型都是不完整的，除非它们用`SimState`填充 - 它们的大小取决于运行的体系结构。可以使用`ty.with_state(state)`执行此操作，该状态返回指定状态的自身副本。 ？？？？

angr有一个依靠`pycparser`的轻量级wrapper，是一个C解析器。

```python
>>> import angr

# note that SimType objects have their __repr__ defined to return their c type name,
# so this function actually returned a SimType instance.
>>> angr.types.parse_type('int')
int

>>> angr.types.parse_type('char **')
char**

>>> angr.types.parse_type('struct aa {int x; long y;}')
struct aa

>>> angr.types.parse_type('struct aa {int x; long y;}').fields
OrderedDict([('x', int), ('y', long)])
```

```python
>>> angr.types.parse_defns("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
{'x': int, 'y': struct llist*}

>>> defs = angr.types.parse_types("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
>>> defs
{'list_node': struct llist}

# if you want to get both of these dicts at once, use parse_file, which returns both in a tuple.

>>> defs['list_node'].fields
OrderedDict([('str', char*), ('next', struct llist*)])

>>> defs['list_node'].fields['next'].pts_to.fields
OrderedDict([('str', char*), ('next', struct llist*)])

# If you want to get a function type and you don't want to construct it manually,
# you have to use parse_defns, not parse_type
>>> angr.types.parse_defns("int x(int y, double z);")
{'x': (int, double) -> int}
```

注册结构体定义以供将来使用 ：

```python
>>> angr.types.define_struct('struct abcd { int x; int y; }')
>>> angr.types.register_types(angr.types.parse_types('typedef long time_t;'))
>>> angr.types.parse_defns('struct abcd a; time_t b;')
{'a': struct abcd, 'b': long}
```

这些类型对象本身并不是那么有用，但可以将它们传递给angr的其他部分以**指定数据类型**。 

### 5.2 Accessing typed data from memory

使用types模块注册的任何类型都可用于从内存中提取数据。 

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware')
>>> s = b.factory.entry_state()
>>> s.mem[0x601048]
<<untyped> <unresolvable> at 0x601048>

>>> s.mem[0x601048].long
<long (64 bits) <BV64 0x4008d0> at 0x601048>

>>> s.mem[0x601048].long.resolved
<BV64 0x4008d0>

>>> s.mem[0x601048].long.concrete
0x4008d0

>>> s.mem[0x601048].abcd
<struct abcd {
  .x = <int (32 bits) <BV32 0x4008d0> at 0x601048>,
  .y = <int (32 bits) <BV32 0x0> at 0x60104c>
} at 0x601048>

>>> s.mem[0x601048].long.resolved
<BV64 0x4008d0>

>>> s.mem[0x601048].long.concrete
4196560L

>>> s.mem[0x601048].deref
<<untyped> <unresolvable> at 0x4008d0>

>>> s.mem[0x601048].deref.string
<string_t <BV64 0x534f534e45414b59> at 0x4008d0>

>>> s.mem[0x601048].deref.string.resolved
<BV64 0x534f534e45414b59>

>>> s.mem[0x601048].deref.string.concrete
'SOSNEAKY'
```

The interface works like this:

- 首先使用 [数组索引] 指定要加载的地址 
- 如果该地址是指针，可以访问`deref`属性以返回内存中存储的地址的`SimMemView`。 
- 然后，只需访问该名称的属性即可为数据指定类型。有关受支持类型的列表，请查看`state.mem.types`。 
- 然后，可以优化类型。任何类型都可以支持细化？？？？。现在，支持的唯一改进是可以通过其成员名称访问结构的任何成员，并且可以索引到字符串或数组以访问该元素 。
- 如果最初指定的地址指向该存储类型的数组，则可以说`.array(n)`将数据视为n个元素的数组。 
- 最后，使用`.resolved`或`.concrete`提取结构化数据。 `.resolved`将返回`bitvector`值，而`.concrete`将返回整数，字符串，数组等值。 
- 或者，可以通过指定已构造的属性链将值存储到内存中。请注意，由于python的工作方式，`x = s.mem[...].prop; x = val` 不起作用，必须使用 `s.mem[...].prop = val`。

如果使用`define_struct`或`register_types`定义结构体，则可以在此处作为一种类型访问它： 

```python
>>> s.mem[b.entry].abcd
<struct abcd {
  .x = <int (32 bits) <BV32 0x8949ed31> at 0x400580>,
  .y = <int (32 bits) <BV32 0x89485ed1> at 0x400584>
} at 0x400580>
```

### 5.3 Working with Calling Conventions

**调用约定**是代码传递参数并通过函数调用返回值的特定方法。虽然angr带有大量预先构建的调用约定，并且有很多逻辑用于为特定情况细化调用约定（例如，浮点参数需要存储在不同的位置），但不足以描述编译器可能生成的所有可能的调用约定。因此，可以**通过描述参数和返回值应该存在的位置来自定义调用约定**。 

angr对调用约定的抽象称为SimCC。可以通过angr对象`factory`使用`b.factory.cc(...)`构建新的`SimCC`实例。

- 将`args`关键字参数作为参数存储位置列表传递 ；
- 将`ret_val`关键字参数作为应存储返回值的位置传递 ；
- 将`func_ty`关键字参数作为函数原型的`SymType`传递 ；
- 不传递参数，使用适合于当前架构的默认值。

要为`args`或`ret_val`参数指定值位置，使用`SimRegArg`或`SimStackArg`类的实例。可以在`factory`找到它们 - `b.factory.cc.Sim * Arg`。 寄存器参数应该使用存储值的寄存器的名称以及寄存器的大小（以字节为单位）进行实例化。堆栈参数应使用进入函数时堆栈指针的偏移量和存储位置的大小（以字节为单位）进行实例化。 

一旦有了SimCC对象，就可以将它与SimState对象一起使用，以更清晰地提取或存储函数参数。有关详细信息，请查看[API文档](http://angr.io/api-doc/angr.html#angr.calling_conventions.SimCC)。或者，可以将其传递给可以使用它来修改自己行为的接口，例如`b.factory.call_state`，或者...... 

### 5.4 Callables

Callables是用于符号执行的外部函数接口（FFI）。callable的基本用法是用`myfunc = b.factory.callable(addr)`创建一个，然后调用它！ `result = myfunc(args，...)`当调用callable时，angr会在给定的地址设置一个`call_state`，将给定的参数转储到内存中，然后根据这个状态运行一个`path_group`，直到所有路径都退出函数。然后，它将所有结果状态合并在一起，从该状态取出返回值，然后返回它。 

所有与state的交互都是在`SimCC`的帮助下进行的，以告知在哪里放置参数以及从何处获取返回值。默认情况下，它使用体系结构的默认值，但如果想自定义，可以在构造可调用对象时在`cc`关键字参数中传递`SimCC`对象。 

可以将符号数据作为函数参数传递。甚至可以将更复杂的数据（如字符串，列表和结构）作为原生python数据（元组用于结构）传递，并且它将尽可能干净地序列化到状态中。如果要指定某个值的指针，可以将其包装在`PointerWrapper`对象中，该对象可通过`b.factory.callable.PointerWrapper`使用。指针包装工作的确切语义有点令人困惑，但它们可以归结为“除非你用`PointerWrapper`或特定的`SimArrayType`指定它，否则任何东西都不会自动包装在指针中，除非它到达终点并且它尚未包装在指针中，并且原始类型是字符串，数组或元组。“相关代码实际上是在`SimCC`中 —— `setup_callsite`函数。 ？？？？

如果不关心调用的实际返回值，可以用`func.perform_call(arg，...)`，然后将填充属性`func.result_state`和`func.result_path_group`。即使正常调用callable，它们实际上也会被填充。 ？？？？

## 6. Claripy

### 6.1 Solver Engine

angr的求解器引擎（solver engine）叫做`Claripy`。 `Claripy`公开了以下设计 :

- Claripy ASTs ( `claripy.ast.Base`的子类) 提供了与具体表达式或符号表达式交互的统一方式。
- `Frontend`为评估这些表达式提供了不同的范式。 例如， `FullFrontend`表达式使用类似SMT求解器后端的东西 来求解表达式 ，而 `LightFrontend`通过使用抽象（和近似）数据域后端来处理。
- 每个`Frontend` 需要在某个时刻对AST进行实际操作和评估。 AST不会自行支持。相反，`Backend`s将AST转换为后端对象（即`BackendConcrete`的python原语，`BackendZ3`的Z3表达式，`BackendVSA`的跨步间隔等）并处理任何适当的状态跟踪对象（state-tracking objects）（例如在`BackendZ3`的情况下跟踪求解器状态）。粗略地说，前端将AST作为输入并使用后端`backend.convert()`转换为后端对象，这些后端对象可以进行评估和推理。 
- `FrontendMixin`自定义`Frontend`的操作。例如，`ModelCacheMixin`缓存来自SMT求解器的解决方案 
- 一个`Frontend`、一些`FrontendMixins`、一些`BACkends`组成了一个claripy `Solver`。

在内部，Claripy无缝地调解多个不同后端的合作 —— 具体的bitvectors，VSA构造和SAT求解器。

大多数angr用户不需要直接与Claripy交互（可能是代表符号表达式的claripy AST对象） ——  angr在内部处理与Claripy的大多数交互。但是，对于处理表达式，理解Claripy可能会有用。 

### 6.2 Claripy ASTs

Claripy ASTs抽象出Claripy支持的数学结构之间的差异。它们在任何类型的底层数据上定义操作树（即`（a + b）/ c`）。 Claripy通过向后端发送请求来处理这些操作在底层对象上的应用。

目前，Claripy支持以下类型的AST： 

| Name | Description                                                  | Supported By (Claripy Backends)        | Example Code                                                 |
| ---- | ------------------------------------------------------------ | -------------------------------------- | ------------------------------------------------------------ |
| BV   | 位向量，可以是符号值（带有名称）或具体值（带有值），大小以bit为单位 | BackendConcrete, BackendVSA, BackendZ3 | -创建32位符号向量: `claripy.BVS('x', 32)`                       -创建32位值向量 `0xc001b3475`: `claripy.BVV(0xc001b3a75, 32)`                                          -创建32位"strided interval" (可查看 VSA 文档) 这可以是1000到2000之间任何可分的10个数字 : `claripy.SI(name='x', bits=32, lower_bound=1000, upper_bound=2000, stride=10)` |
| FP   | 浮点数，可以是符号值（带名称）或具体值（带值）               | BackendConcrete, BackendZ3             | TODO                                                         |
| Bool | 布尔运算（True或False）                                      | BackendConcrete, BackendVSA, BackendZ3 | `claripy.BoolV(True)`, or `claripy.true`or `claripy.false`, or 通过组合两个AST (i.e., `claripy.BVS('x', 32) < claripy.BVS('y', 32)` |

所有上述创建代码都返回claripy.AST对象，然后可以在其上执行操作 。

AST提供了一些有用的操作 ：

```python
>>> import claripy

>>> bv = claripy.BVV(0x41424344, 32)

# Size - you can get the size of an AST with .size()
>>> assert bv.size() == 32

# Reversing - .reversed is the reversed version of the BVV
>>> assert bv.reversed is claripy.BVV(0x44434241, 32)
>>> assert bv.reversed.reversed is bv

# Depth - you can get the depth of the AST
>>> print bv.depth
>>> assert bv.depth == 1
>>> x = claripy.BVS('x', 32)
>>> assert (x+bv).depth == 2
>>> assert ((x+bv)/10).depth == 3
```

在AST上应用条件（==，！=等）将返回表示正在执行的条件的AST 。例如：

```python
>>> r = bv == x
>>> assert isinstance(r, claripy.ast.Bool)

>>> p = bv == bv
>>> assert isinstance(p, claripy.ast.Bool)
>>> assert p.is_true()
```

条件可以通过不同方式组合：

```python
>>> q = claripy.And(claripy.Or(bv == x, bv * 2 == x, bv * 3 == x), x == 0)
>>> assert isinstance(p, claripy.ast.Bool)
```

通常，Claripy支持所有正常的python操作（+， - ，|，==等），并通过Claripy实例对象提供其他操作，可用操作如下：

| Name        | Description                                                  | Example                                                      |
| ----------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| LShR        | Logically shifts a bit expression (BVV, BV, SI) to the right. | `claripy.LShR(x, 10)`                                        |
| SignExt     | Sign-extends a bit expression.                               | `claripy.SignExt(32, x)` or `x.sign_extend(32)`              |
| ZeroExt     | Zero-extends a bit expression.                               | `claripy.ZeroExt(32, x)` or `x.zero_extend(32)`              |
| Extract     | Extracts the given bits (zero-indexed from the *right*, inclusive) from a bit expression. | Extract the rightmost byte of x: `claripy.Extract(7, 0, x)` or `x[7:0]` |
| Concat      | Concatenates several bit expressions together into a new bit expression. | `claripy.Concat(x, y, z)`                                    |
| RotateLeft  | Rotates a bit expression left.                               | `claripy.RotateLeft(x, 8)`                                   |
| RotateRight | Rotates a bit expression right.                              | `claripy.RotateRight(x, 8)`                                  |
| Reverse     | Reverses a bit expression.                                   | `claripy.Reverse(x)` or `x.reversed`                         |
| And         | Logical And (on boolean expressions)                         | `claripy.And(x == y, x > 0)`                                 |
| Or          | Logical Or (on boolean expressions)                          | `claripy.Or(x == y, y < 10)`                                 |
| Not         | Logical Not (on a boolean expression)                        | `claripy.Not(x == y)` is the same as `x != y`                |
| If          | An If-then-else                                              | Choose the maximum of two expressions: `claripy.If(x > y, x, y)` |
| ULE         | Unsigned less than or equal to.                              | Check if x is less than or equal to y: `claripy.ULE(x, y)`   |
| ULT         | Unsigned less than.                                          | Check if x is less than y: `claripy.ULT(x, y)`               |
| UGE         | Unsigned greater than or equal to.                           | Check if x is greater than or equal to y: `claripy.UGE(x, y)` |
| UGT         | Unsigned greater than.                                       | Check if x is greater than y: `claripy.UGT(x, y)`            |
| SLE         | Signed less than or equal to.                                | Check if x is less than or equal to y: `claripy.SLE(x, y)`   |
| SLT         | Signed less than.                                            | Check if x is less than y: `claripy.SLT(x, y)`               |
| SGE         | Signed greater than or equal to.                             | Check if x is greater than or equal to y: `claripy.SGE(x, y)` |
| SGT         | Signed greater than.                                         | Check if x is greater than y: `claripy.SGT(x, y)`            |

注意：默认的python>，<，> =和<=运算符的操作数在Claripy中是**无符号**的。这与他们在Z3中的行为不同。

### 6.3 Solvers

与Claripy交互的主要方面是Claripy Solvers。求解器公开API以不同方式解释AST并返回可用值。有几种不同的求解器。 

| Name              | Description                                                  |
| ----------------- | ------------------------------------------------------------ |
| Solver            | 类似于`z3.Solver()`。是一个跟踪符号变量约束的求解器，并使用约束求解器（当前为Z3）来计算符号表达式。 |
| SolverVSA         | 该求解器使用VSA来推理值。它是一个近似求解器，但在不执行实际约束求解的情况下生成值。 |
| SolverReplacement | 此求解器充当子求解器的传递，允许动态替换表达式。它被其他求解器用作帮助器，可以直接用于实现奇异分析。 ？？？？ |
| SolverHybrid      | 该求解器结合了`SolverReplacement`和`Solver`（VSA和Z3）以允许近似值。可以指定是否需要评估的精确结果，此求解器将完成剩下的工作。 |
| SolverComposite   | 此求解器实现优化（解决较小的约束集以加速约束求解）。         |

例子：

```python
# create the solver and an expression
>>> s = claripy.Solver()
>>> x = claripy.BVS('x', 8)

# now let's add a constraint on x
>>> s.add(claripy.ULT(x, 5))

>>> assert sorted(s.eval(x, 10)) == [0, 1, 2, 3, 4]
>>> assert s.max(x) == 4
>>> assert s.min(x) == 0

# we can also get the values of complex expressions
>>> y = claripy.BVV(65, 8)
>>> z = claripy.If(x == 1, x, y)
>>> assert sorted(s.eval(z, 10)) == [1, 65]

# and, of course, we can add constraints on complex expressions
>>> s.add(z % 5 != 0)
>>> assert s.eval(z, 10) == (1,)
>>> assert s.eval(x, 10) == (1,) # interestingly enough, since z can't be y, x can only be 1!
```

自定义求解器可以通过组合Claripy前端（处理与SMT求解器或底层数据域的实际交互的类）和前端混合的一些组合（处理诸如缓存，过滤掉重复约束，进行机会简化等）来构建。 ？？？？

### 6.4 Claripy Backends

后端是Claripy的主力。 当必须进行实际计算时，Claripy会将这些AST推送到可由后端本身处理的对象中。这为外界提供了统一的界面，同时允许Claripy支持不同类型的计算。例如，`BackendConcrete`为具体的`bitvectors`和布尔值提供计算支持，`BackendVS`A引入了VSA构造，例如`StridedIntervals`（详细说明了对它们执行操作时会发生什么，`BackendZ3`提供对符号变量和约束求解的支持。 

后端实现一组函数。对于所有这些函数，“public”版本应该能够处理claripy的AST对象，而“private”版本应该只处理特定于后端本身的对象。这与Python习语不同：公共函数将命名为func（），而私有函数将命名为_func（）。所有函数都应返回后端在其私有方法中可用的对象。如果无法做到这一点（即，正在尝试后端无法处理的某些功能），则后端应该引发`BackendError`。在这种情况下，Claripy将继续进入其列表中的下一个后端。 

所有后端都必须实现`convert()`函数。此函数接收`claripy AST`并应返回后端可以在其私有方法中处理的对象。后端还应该实现`_convert()`方法，该方法将接收任何不是`claripy AST`对象的东西（即，来自不同后端的整数或对象）。如果`convert()`或`_convert`收到后端无法转换为内部可用格式的内容，则后端应该引发`BackendError`，因此不会用于该对象。所有后端还必须实现当前引发`NotImplementedError()`的基本`Backend`抽象类的所有函数。？？？？

Claripy与其后端的合作如下：后端应该能够在其私有函数中处理从私有或公共函数返回的任何对象。 Claripy永远不会将对象（不是来自该后端的私有或公共函数的返回值）传递给任何后端私有函数。  一个例外是`convert()`和`_convert()`，因为Claripy可以尝试将任何东西填充到`_convert()`中以查看后端是否可以处理该类型的对象。 ？？？？

#### Backend Objects

为了对AST执行实际有用的计算，Claripy使用后端对象（BackendObject）。 BackendObject是AST表示的操作的结果。 Claripy希望从各自的后端返回这些对象，并将这些对象传递到后端的其他函数中。 

## 7. Symbolic memory addressing

angr支持符号内存寻址，内存中的偏移可能是符号。当地址用作写入目标时，angr会将符号地址具体化。用户倾向于期望符号写入进行纯粹符号化地处理，或“符号化地”处理符号读取，但默认不是这样。这是可配置的。 

地址解析行为由具体化策略（*concretization strategies* ）控制，这些策略是`angr.concretization_strategies.SimConcretizationStrategy`的子类。 读取（reads）的具体化策略在`state.memory.read_strategies`中设置，写（writes）的策略在`state.memory.write_strategies`中设置。 按顺序调用这些策略，直到其中一个能够解析符号索引的地址。通过设置自己的具体化策略（或通过使用SimInspect `address_concretization`断点），可以更改angr解析符号地址的方式。？？？？

 例如，angr写入（writes）的默认具体化策略是 ：

1. 一种条件具体化策略，允许对使用`angr.plugins.symbolic_memory.MultiwriteAnnotation`注释的任何索引进行符号写入（最大范围为128种可能的解决方案）。 
2. 一种简单的策略，它简单地选择符号索引的最大可能解。 

要为所有索引启用符号写入，可以在创建状态时添加`SYMBOLIC_WRITE_ADDRESSES`状态选项，也可以手动将`angr.concretization_strategies.SimConcretizationStrategyRange`对象插入`state.memory.write_strategies`。 策略对象采用单个参数，这是在放弃当前策略并继续下一个（可能是非符号）策略之前允许的最大可能解决方案范围。 ？？？？

### Writing concretization strategies