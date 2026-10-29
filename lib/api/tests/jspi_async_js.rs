#![cfg(all(feature = "experimental-async", feature = "js", target_arch = "wasm32"))]

use js_sys::Promise;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::wasm_bindgen_test;
use wasmer::{
    Function, FunctionType, Instance, Module, RuntimeError, Store, Type, TypedFunction, Value,
    imports,
};

#[wasm_bindgen_test]
async fn typed_async_host_and_guest_calls_use_jspi() {
    let mut store = Store::default();
    let module = Module::new(
        &store,
        r#"
        (module
          (import "host" "increment" (func $increment (param i32) (result i32)))
          (func (export "compute") (param i32) (result i32)
            local.get 0
            call $increment))
        "#,
    )
    .unwrap();
    let increment = Function::new_typed_async(&mut store, async move |value: i32| {
        JsFuture::from(Promise::resolve(&JsValue::UNDEFINED))
            .await
            .unwrap();
        value + 1
    });
    let imports = imports! {
        "host" => {
            "increment" => increment,
        }
    };
    let instance = Instance::new(&mut store, &module, &imports).unwrap();
    let compute: TypedFunction<i32, i32> = instance
        .exports
        .get_typed_function(&store, "compute")
        .unwrap();

    let result = compute.call_async(&store.into_async(), 41).await.unwrap();
    assert_eq!(result, 42);
}

#[derive(Debug, thiserror::Error)]
#[error("guest exited with {0}")]
struct Exited(i32);

#[wasm_bindgen_test]
async fn async_host_user_errors_reach_the_caller() {
    let mut store = Store::default();
    let module = Module::new(
        &store,
        r#"
        (module
          (import "host" "exit" (func $exit (param i32)))
          (func (export "run")
            i32.const 42
            call $exit))
        "#,
    )
    .unwrap();
    let exit = Function::new_async(
        &mut store,
        FunctionType::new([Type::I32], []),
        |args: &[Value]| {
            let status = args[0].unwrap_i32();
            async move { Err(RuntimeError::user(Box::new(Exited(status)))) }
        },
    );
    let imports = imports! {
        "host" => {
            "exit" => exit,
        }
    };
    let instance = Instance::new(&mut store, &module, &imports).unwrap();
    let run = instance.exports.get_function("run").unwrap();

    let err = run
        .call_async(&store.into_async(), vec![])
        .await
        .unwrap_err();
    assert_eq!(err.downcast::<Exited>().unwrap().0, 42);
}
