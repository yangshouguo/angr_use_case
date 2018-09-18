# Simulation Managers

angr中最重要的控制接口就是SimulationManager(模拟器管理接口，后面简写为simgr),这个类可以让你去在多组执行状态上进行模拟的控制符号执行（同时模拟执行多个state），应用一些搜索策略去探索一个程序的状态空间。


Simulation管理器可以让你更方便的控制多个程序状态。所有程序状态被放在 “stashes” 里面，你可以随意的对状态进行向前继续执行，过滤，合并状态，或者移除。

你也可以合并两个并不同步执行的状态。

默认的stash是 “active stash”

## Stepping
simgr 最基本的能力就是继续执行一个基本块的stash中所有的state

使用 `.step()` 函数来做

	>>> import angr
	>>> proj = angr.Project('examples/fauxware/fauxware', auto_load_libs=False)
	>>> state = proj.factory.entry_state()
	>>> simgr = proj.factory.simgr(state)
	>>> simgr.active
	[<SimState @ 0x400580>]
	>>> simgr.step()
	>>> simgr.active
	[<SimState @ 0x400540>]


statsh模型真正的能力是，当一个state遇到一个符号执行的分支，所有的分支状态都会放在stash中，你可以同步的去继续执行这些状态。

如果你不关心有关分支控制只是想运行程序，你可以直接用 `.run()` 函数。

	# Step until the first symbolic branch
	>>> while len(simgr.active) == 1:
	... simgr.step()
	>>> simgr
	<SimulationManager with 2 active>
	>>> simgr.active
	[<SimState @ 0x400692>, <SimState @ 0x400699>]
	# Step until everything terminates
	>>> simgr.run()
	>>> simgr
	<SimulationManager with 3 deadended>

上面代码使用 `.run()` 函数之后获得3个deadended状态！

当一个状态在执行时没有后继代码，例如，当程序运行到 `exit` 系统调用时，那么当前状态就会从**active stash**中移除，放置在**deadended stash**中。

## Stash Management

想要将状态在stash之间进行移动，使用`.move()`函数，该函数的参数为`from_stash, to_stash[, filter_func]`,例如，移动一个有字符串输出的程序状态。

	>>> simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s:
	'Welcome' in s.posix.dumps(1))
	>>> simgr
	<SimulationManager with 2 authenticated, 1 deadended>

这样就创建了一个新的stash `authenticated` . 所有在这个新的stash中的程序状态的输出中都包含"Welcome"字符串

每个stash都是一个列表，你可以使用下标来指定某个程序状态。

## Stash types

有一些（内置）stash是用来对一些特殊种类的程序状态的。

|Stash|Description|
|---|---|
|active|This stash contains the states that will be stepped by default, unless an alternate stash is specified.|
|deadended|A state goes to the deadended stash when it cannot continue the execution for some reason, including no more valid instructions, unsat state of all of its successors, or an invalid instruction pointer|
|pruned|When using LAZY_SOLVES , states are not checked for satisfiability unless absolutely necessary. When a state is found to be unsat in the presence of LAZY_SOLVES , the state hierarchy is traversed to identify when, in its history, it initially became unsat. All states that are descendants of that point (which will also be unsat, since a state cannot become un-unsat) are pruned and put in this stash.|
|unconstrained|If the save_unconstrained option is provided to the SimulationManager constructor, states that are determined to be unconstrained (i.e., with the instruction pointer controlled by user data or some other source of symbolic data) are placed here.|
|unsat|If the save_unsat option is provided to the SimulationManager constructor, states that are determined to be unsatisfiable (i.e., they have constraints that are contradictory, like the input having to be both "AAAA" and "BBBB" at the same time) are placed here|

其他的stash 例如`errored`，是包含执行时出现错误的程序状态，此时该状态将会被封装成一个`ErrorRecord`对象，该对象包含程序状态和其引发的错误，然后该对象被放置在`errored` stash中。

## Simple Exploration

一个符号执行中非常常见的操作就是将程序状态执行到某一个确切的地址。同时丢弃所有没有到达该地址的其他状态。使用`.explore()`方法可以做到。

当使用 `.explore()`函数的 *find* 参数，程序状态会一直执行直到状态满足 *find* 条件，这个条件可以是

* 1.指定一个程序停止运行的地址 

* 2.指定多个程序停止运行的地址 

* 3.某个函数  ？？？？  a function which takes a state and returns whether it meets some criteria

当任意一个位于`active stash`中的程序状态满足find条件之后，该状态就会被置于 `found` stash中，执行也会停止。

与find类似，你可以指定avoid参数，当一个程序状态满足avoid条件时，就会被置于`avoided`stash中，执行也会停止。

*num_find*参数控制被`explor()`发现的程序状态数量,默认是1

下面是一个例子：

First, we load the binary.

	>>> proj = angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')

Next, we create a SimulationManager.

	>>> simgr = proj.factory.simgr()

Now, we symbolically execute until we find a state that matches our condition (i.e., the "win"
condition).

	>>> simgr.explore(find=lambda s: "Congrats" in s.posix.dumps(1))

<SimulationManager with 1 active, 1 found>

Now, we can get the flag out of that state!

	>>> s = simgr.found[0]
	>>> print s.posix.dumps(1)

Enter password: Congrats!

	>>> flag = s.posix.dumps(0)
	>>> print(flag)

	g00dJ0B!

# Exploration Techniques

...


# Simulation and Instrumentation

当angr模拟执行时，会调用很多引擎去模拟给定代码段在给定输入状态下的作用。

angr的执行的核心简单按照顺序尝试应用所有的可用的引擎，并利用第一个可用的引擎去处理和执行代码。如下是angr尝试的引擎的顺序：

1. failure engine : 上一步代码执行到一个不可继续的代码
2. syscall engine : 上一步代码执行到一个系统调用
3. hook engine : 当前地址被hook
4. unicorn engine : 当*UNICORN*状态选项被激活,并且当前状态中没有符号值
5. VEX engine : 最后的应对方式

