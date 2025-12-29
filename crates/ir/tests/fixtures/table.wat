(module
  (table 2 funcref)
  (func $f1 (result i32)
    i32.const 1
  )
  (func $f2 (result i32)
    i32.const 2
  )
  (elem (i32.const 0) $f1 $f2)
)
