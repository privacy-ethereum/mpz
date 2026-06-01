(module
  (func (export "factorial") (param $n i32) (result i32)
    (local $result i32)
    i32.const 1
    local.set $result

    (block $exit
      (loop $loop
        local.get $n
        i32.const 1
        i32.le_s
        br_if $exit

        local.get $result
        local.get $n
        i32.mul
        local.set $result

        local.get $n
        i32.const 1
        i32.sub
        local.set $n

        br $loop
      )
    )

    local.get $result
  )
)
