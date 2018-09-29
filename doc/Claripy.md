
val = x = BV()

#BitVector Manipulation 位向量操作

* SignExt 将位向量用n位特定值对齐到左边 `x.sign_extend(n)`
* ZeroExt 将位向量用n位0对齐到左边 `x.zero_extend(n)`
* Extract 从一个表达式中提取给定位数(最右边下标是0)  例如提取一个字节数据 `x[7:0]`
* Concat 将任意数量的表达式-拼接在一起形成一个新的表达式 `x.concat(y, ...)`

# 其他操作

* 切分位向量 `val.chop(n)`
* 反转位向量 `val.reversed`
* 位向量的位数 `val.length`
* 是否AST中有符号值 `val.symbolic`
* 获得所有符号值的名字 `val.variables`
