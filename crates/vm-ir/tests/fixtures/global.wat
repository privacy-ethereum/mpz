(module
  (global $g1 i32 (i32.const 100))
  (global $g2 (mut i32) (i32.const 200))
  (func (export "get_g1") (result i32)
    global.get $g1
  )
  (func (export "get_g2") (result i32)
    global.get $g2
  )
  (func (export "set_g2") (param i32)
    local.get 0
    global.set $g2
  )
)
