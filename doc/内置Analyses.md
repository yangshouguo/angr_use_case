## Built-in Analyses

### 1. CFGAccurate

#### 1.1 General ideas

可以对二进制文件执行的基本分析是控制流图。 CFG是一个图，基本块作为节点，跳转/调用/ rets /等作为边缘。 

在angr中，可以生成两种类型的CFG：**快速CFG（CFGFast）和精确CFG（CFGAccurate）**。生成快速CFG通常比生成精确CFG快得多。 

创建精确CFG：

```python
>>> import angr
# load your project
>>> b = angr.Project('/bin/true', load_options={'auto_load_libs': False})

# generate an accurate CFG
>>> cfg = b.analyses.CFGAccurate(keep_state=True)
```

定制化CFG：

| Option                           | Description                                                  |
| -------------------------------- | ------------------------------------------------------------ |
| context_sensitivity_level        | 设置分析的上下文敏感度级别 。默认为1。                       |
| starts                           | 地址列表（list），用作分析的入口点。                         |
| avoid_runs                       | 要在分析中忽略的地址列表（list）。                           |
| call_depth                       | 将分析的深度限制为某些数字调用。这对于检查特定函数可以直接跳转到哪些函数（通过将call_depth设置为1）非常有用。 |
| initial_state                    | 可以向CFG提供初始状态，它将在整个分析过程中使用。            |
| keep_state                       | 为了节省内存，默认情况下会丢弃每个基本块的状态。如果keep_state为True，则状态将保存在CFGNode中。 |
| enable_symbolic_back_traversal   | 是否启用强化技术来解决间接跳转 。                            |
| enable_advanced_backward_slicing | 是否启用另一种强化技术来解决直接跳转                         |
| more!                            | 检查`b.analyses.CFGAccurate`上的`docstring`以获取更多最新选项 |

#### 1.2 上下文敏感级别

angr通过执行每个基本块并查看它的去向来构造CFG。这引入了一些挑战：基本块在不同的上下文中可以有不同的行为。例如，如果块在函数返回中结束，则该返回的目标将不同，取决于包含该基本块的函数的不同调用者。

 从概念上讲，上下文敏感度级别是要在`callstack`上保留的此类调用者的数量。

```python
void error(char *error)
{
    puts(error);
}

void alpha()
{
    puts("alpha");
    error("alpha!");
}

void beta()
{
    puts("beta");
    error("beta!");
}

void main()
{
    alpha();
    beta();
}
```

上面的示例有四个调用链：`main> alpha> puts`，`main> alpha> error> puts`和`main> beta> puts`，`main> beta> error> puts`。虽然在这种情况下，angr可能会执行两个调用链，但这对于较大的二进制文件来说变得不可行。因此，angr执行具有受上下文敏感度级别限制的状态的块。也就是说，为每个被调用的唯一上下文重新分析每个函数。 （**在不同上下文下，对相同函数的调用，都会进行重新分析**）

例如，给定不同的上下文敏感度级别，将使用以下上下文分析上面的`puts()`函数 ：

| Level | Meaning                                              | Contexts                                                     |
| ----- | ---------------------------------------------------- | ------------------------------------------------------------ |
| 0     | Callee-only（仅被调用者）                            | `puts`                                                       |
| 1     | One caller, plus callee（一个调用者，和被调用者）    | `alpha>puts` `beta>puts` `error>puts`                        |
| 2     | Two callers, plus callee（两个调用者，和被调用者）   | `alpha>error>puts` `main>alpha>puts` `beta>error>puts` `main>beta>puts` |
| 3     | Three callers, plus callee（三个调用者，和被调用者） | `main>alpha>error>puts` `main>alpha>puts` `main>beta>error>puts` `main>beta>puts` |

增加上下文敏感度级别的好处是可以从CFG中收集更多信息。例如，当上下文敏感度为1时，CFG将显示，当从`alpha`调用时，`puts`返回到`alpha`，当从`error`调用时，`puts`返回到`error`，依此类推。上下文敏感度为0时，从`alpha`或`error`调用， CFG只显示`puts`返回到`alpha`，`beta`和`error` (这三个作为一个整体)。具体而言，这是IDA中使用的上下文敏感度级别。

增加上下文敏感度级别的缺点是它会以指数方式增加分析时间。 ？？？？

#### 1.3 使用CFG

CFG的核心是[NetworkX](https://networkx.github.io/) di-graph。所有正常的NetworkX API都可用： 

```python
>>> print "This is the graph:", cfg.graph
>>> print "It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges()))
```

CFG图的节点是CFGNode类的实例。由于上下文敏感性，给定的基本块可以在图中具有多个节点（对于多个上下文） 。

#### 1.4 查看CFG 

控制流图形渲染是一个难题。 angr没有提供任何用于渲染CFG分析输出的内置机制，并且尝试使用传统的图形渲染库（如matplotlib）将导致无法使用的图像。 

在[axt的angr-utils存储库](https://github.com/axt/angr-utils)中有一种查看angr CFG的解决方案 。

#### 1.5 共享库

CFG分析不区分不同二进制对象的代码。这意味着默认情况下，它将尝试**通过加载的共享库分析控制流**。这几乎不是预期的行为，因为这可能会将分析时间延长到几天。要加载没有共享库的二进制文件，将以下关键字参数添加到`Project`构造函数中：`load_options = {'auto_load_libs'：False} `

#### 1.6 函数管理器（Function Manager）

CFG结果生成一个名为`Function Manager`的对象，可通过`cfg.kb.functions`访问。此对象最常见的用例是像*字典*一样访问它。它将地址映射到`Function`对象，可以获取有关函数的属性。 

```python
>>> entry_func = cfg.kb.functions[b.entry]
```

`Functions`的重要属性：

- `entry_func.block_addrs` ：该函数的一组基本块的起始地址（类型：*dictionary-keyiterator*）。
- `entry_func.blocks` ：属于该函数的一组基本块，可以使用`capstone`进行`explore`和反汇编 ？？？？。
- `entry_func.string_references()` ：返回函数中任何点引用的所有常量字符串的列表（list）。它们被格式化为`(addr，string)`元组，其中`addr`是字符串所在的二进制数据部分中的地址，而`string`是包含字符串值的python字符串。 
- `entry_func.returning`：是一个布尔值，表示函数是否可以返回。 `False`表示所有路径都不返回。 
- `entry_func.callable`：是一个指向此函数的`angr Callable`对象。可以像使用python参数的python函数一样调用它并获取实际结果（可能是符号）。？？？？ 
- `entry_func.transition_graph`： 是一个NetworkX DiGraph，描述了函数本身内的控制流。它类似于IDA在每个函数级别上显示的控制流图。 
- `entry_func.name` ：函数名字。
- `entry_func.has_unresolved_calls` and `entry.has_unresolved_jumps`： 与检测CFG内的不精确有关。有时，分析无法检测间接调用或跳转的可能目标是什么。如果在函数内发生这种情况，则该函数将相应的`has_unresolved_ *`值设置为`True`。 
- `entry_func.get_call_sites()`： 返回所有以调用其他函数（的语句）结束的基本块的地址列表。 
- `entry_func.get_call_target(callsite_addr)`： 将从call site地址列表中给出`callsite_addr`，返回该callsite将会调用的位置。 ？？？？
- `entry_func.get_call_return(callsite_addr)` ： 将从call site地址列表中给出`callsite_addr`，返回该callsite将会返回的位置。 ？？？？

### 2. 后向切片

从程序中的目标构造后向切片，并且该切片中的所有数据流在目标处结束。 

angr有一个内置的`analysis`，称为`BackwardSlice`，用于构造一个后向程序切片。

#### 2.1 First Step

构建`BackwardSlice`需要如下信息作为输入：

- CFG：程序控制流图，必须是CFGAccurate。
- Target：后向切片终止的最终目标。
- CDG（可选）：来自CFG的控制依赖图（CDG），angr有内置的analysis`CDG`。
- DDG（可选）：建立在CFG上的数据依赖图（DDG），angr有内置的analysis`DDG`。

```python
>>> import angr
# Load the project
>>> b = angr.Project("examples/fauxware/fauxware", load_options={"auto_load_libs": False})

# Generate a CFG first. In order to generate data dependence graph afterwards,
# you’ll have to keep all input states by specifying keep_state=True. Feel free 
# to provide more parameters (for example, context_sensitivity_level) for CFG 
# recovery based on your needs.
>>> cfg = b.analyses.CFGAccurate(context_sensitivity_level=2, keep_state=True)

# Generate the control dependence graph
>>> cdg = b.analyses.CDG(cfg)

# Build the data dependence graph. It might take a while. Be patient!
>>> ddg = b.analyses.DDG(cfg)

# See where we wanna go... let’s go to the exit() call, which is modeled as a 
# SimProcedure.
>>> target_func = cfg.kb.functions.function(name="exit")
# We need the CFGNode instance
>>> target_node = cfg.get_any_node(target_func.addr)

# Let’s get a BackwardSlice out of them!
# `targets` is a list of objects, where each one is either a CodeLocation 
# object, or a tuple of CFGNode instance and a statement ID. Setting statement 
# ID to -1 means the very beginning of that CFGNode. A SimProcedure does not 
# have any statement, so you should always specify -1 for it.
>>> bs = b.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])

# Here is our awesome program slice!
>>> print bs
```

有时很难获取数据依赖图DDG，可以只依赖于CFG进行切片。（所以DDG是可选项）

```python
>>> bs = b.analyses.BackwardSlice(cfg, control_flow_slice=True) #出错，至少需要4个参数，只提供了3个
BackwardSlice (to [(<CFGNode exit (0x10000a0) [0]>, -1)])
```

#### 2.2 使用`BackwardSlice`对象

##### 成员

| Member             | Mode     | Meaning                                                      |
| ------------------ | -------- | ------------------------------------------------------------ |
| runs_in_slice      | CFG-only | `networkx.DiGraph`实例，显示程序片中基本块和`SimProcedures`的地址，以及它们之间的转换 |
| cfg_nodes_in_slice | CFG-only | `networkx.DiGraph`实例，在程序切片中显示`CFGNodes`和它们之间的转换 |
| chosen_statements  | With DDG | 将基本块地址映射到作为程序切片的一部分的语句ID列表的dict     |
| chosen_exits       | With DDG | 将基本块地址映射到“exits”列表的字典。列表中的每个`exit`都是程序切片中的有效转换（ transition ） |

selected_exit中的每个“exit”都是一个包含语句ID和目标地址列表的元组。例如，“exit”可能如下所示 ：

```python
(35, [ 0x400020 ])
```

如果“exit”是基本块的默认出口，它将如下所示： 

```python
(“default”, [ 0x400085 ])
```

### 3. 函数识别

识别器使用测试用例来标识CGC二进制文件中的公共库函数。它通过查找有关堆栈变量/参数的一些基本信息进行预过滤。

```python
>>> import angr

# get all the matches
>>> p = angr.Project("../binaries/tests/i386/identifiable")
>>> idfer = p.analyses.Identifier() # 会出现段错误？？？？
# note that .run() yields results so make sure to iterate through them or call list() etc
>>> for addr, symbol in idfer.run():
...     print hex(addr), symbol

0x8048e60 memcmp
0x8048ef0 memcpy
0x8048f60 memmove
0x8049030 memset
0x8049320 fdprintf
0x8049a70 sprintf
0x8049f40 strcasecmp
0x804a0f0 strcmp
0x804a190 strcpy
0x804a260 strlen
0x804a3d0 strncmp
0x804a620 strtol
0x804aa00 strtol
0x80485b0 free
0x804aab0 free
0x804aad0 free
0x8048660 malloc
0x80485b0 free
```