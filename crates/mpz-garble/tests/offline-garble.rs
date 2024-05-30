use mpz_circuits::{circuits::AES128, types::StaticValueType};
use mpz_common::executor::test_st_executor;
use mpz_ot::ideal::ot::ideal_ot;

use mpz_garble::{config::Visibility, Evaluator, Generator, GeneratorConfigBuilder, ValueMemory};

#[tokio::test]
async fn test_offline_garble() {
    let (mut ctx_a, mut ctx_b) = test_st_executor(8);
    let (mut ot_send, mut ot_recv) = ideal_ot();

    let gen = Generator::new(
        GeneratorConfigBuilder::default().build().unwrap(),
        [0u8; 32],
    );
    let ev = Evaluator::default();

    let key = [69u8; 16];
    let msg = [42u8; 16];

    let key_typ = <[u8; 16]>::value_type();
    let msg_typ = <[u8; 16]>::value_type();
    let ciphertext_typ = <[u8; 16]>::value_type();

    let gen_fut = async {
        let mut memory = ValueMemory::default();

        let key_ref = memory
            .new_input("key", key_typ.clone(), Visibility::Private)
            .unwrap();
        let msg_ref = memory
            .new_input("msg", msg_typ.clone(), Visibility::Blind)
            .unwrap();
        let ciphertext_ref = memory
            .new_output("ciphertext", ciphertext_typ.clone())
            .unwrap();

        gen.generate_input_encoding(&key_ref, &key_typ);
        gen.generate_input_encoding(&msg_ref, &msg_typ);

        gen.generate(
            &mut ctx_a,
            AES128.clone(),
            &[key_ref.clone(), msg_ref.clone()],
            &[ciphertext_ref.clone()],
            false,
        )
        .await
        .unwrap();

        memory.assign(&key_ref, key.into()).unwrap();

        gen.setup_assigned_values(
            &mut ctx_a,
            &memory.drain_assigned(&[key_ref.clone(), msg_ref.clone()]),
            &mut ot_send,
        )
        .await
        .unwrap();

        gen.get_encoding(&ciphertext_ref).unwrap()
    };

    let ev_fut = async {
        let mut memory = ValueMemory::default();

        let key_ref = memory
            .new_input("key", key_typ.clone(), Visibility::Blind)
            .unwrap();
        let msg_ref = memory
            .new_input("msg", msg_typ.clone(), Visibility::Private)
            .unwrap();
        let ciphertext_ref = memory
            .new_output("ciphertext", ciphertext_typ.clone())
            .unwrap();

        ev.receive_garbled_circuit(
            &mut ctx_b,
            AES128.clone(),
            &[key_ref.clone(), msg_ref.clone()],
            &[ciphertext_ref.clone()],
        )
        .await
        .unwrap();

        memory.assign(&msg_ref, msg.into()).unwrap();

        ev.setup_assigned_values(
            &mut ctx_b,
            &memory.drain_assigned(&[key_ref.clone(), msg_ref.clone()]),
            &mut ot_recv,
        )
        .await
        .unwrap();

        _ = ev
            .evaluate(
                &mut ctx_b,
                AES128.clone(),
                &[key_ref.clone(), msg_ref.clone()],
                &[ciphertext_ref.clone()],
            )
            .await
            .unwrap();

        ev.get_encoding(&ciphertext_ref).unwrap()
    };

    let (ciphertext_full_encoding, ciphertext_active_encoding) = tokio::join!(gen_fut, ev_fut);

    let decoding = ciphertext_full_encoding.decoding();
    let ciphertext: [u8; 16] = ciphertext_active_encoding
        .decode(&decoding)
        .unwrap()
        .try_into()
        .unwrap();

    let expected: [u8; 16] = {
        use aes::{
            cipher::{BlockEncrypt, KeyInit},
            Aes128,
        };

        let mut msg = msg.into();

        let cipher = Aes128::new_from_slice(&key).unwrap();
        cipher.encrypt_block(&mut msg);

        msg.into()
    };

    assert_eq!(ciphertext, expected)
}
