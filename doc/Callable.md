
## Callables
Callables是一些符号执行的外部接口。
基本使用方式是创建对象

`myfunc = b.factory.callable(addr)`

然后调用这个callable对象` result = myfunc(args, ...) `

当你调用这个函数的时候，angr会在给定的地址处生成一个`call_state`，把传的参数放到内存中，然后基于这个`call_state`运行一个`path_group`，直到所有的执行路径都从该函数退出。然后，angr将所有的结果状态合并，得到最终的执行状态，取出返回值，并且返回。

所有的与执行状态`state`的交互都是通过`SimCC`,通过它可以指定将函数参数放在哪里，从哪里获得返回值。

angr默认对每个架构都有各自的参数放置和返回值取值方式。但是如果你想自定义，你在构造`callable`对象的时候可以将一个`SimCC`对象传递给`cc`参数

你可以传递符号值给作为函数参数，这样angr仍旧会正常工作。你甚至可以传递更加复杂的数据，例如字符串，数组，或者python内置数据类型（structures as native python data）。
所有传递的参数都将被序列化然后放置在执行状态中`state`，如果你想指定一个指向某一个值的指针，你可以将其封装成`PointerWrapper`,即`b.factory.callable.PointerWrapper`.
这个对象的工作原理比较复杂，总的可以归结为 **除非你指定参数为`PointerWrapper`或者一个特殊的`SimArrayType`,否则参数不会被自动封装成指针除非必要，或者原数据是字符串，数据，元组并且这些数据没有被封装成`PointerWrapper`**
相关代码在SimCC -- 在`setup_callsite`函数中

如果你不在意函数的实际返回值，你可以调用 `func.perform_call(arg,...)`,然后属性值`func.result_state`和`func.result_path_group`将被填充结果，其实当你直接调用该函数的时候这两个属性也会被赋值。
