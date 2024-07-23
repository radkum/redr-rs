mod error;
mod sandbox;

use std::{collections::BTreeSet, io::ErrorKind};

use ansi_term::Colour::{Green, Red};
use common::utils::{convert_sha256_to_string, sha256_from_string};

use crate::{error::SandboxError, sandbox::perform_sandboxing};

pub fn sandbox_file(file_path: &str, store_path: &str) -> Result<(), SandboxError> {
    let calls = sandbox_path(file_path)?;

    let file_name = file_path
        .split("\\")
        .collect::<Vec<_>>()
        .pop()
        .ok_or(std::io::Error::new(ErrorKind::NotFound, "File to analyze not found"))?;
    let sig_store = signatures::deserialize_sig_store_from_path(store_path)?;

    //todo: remove unwrap
    let sha_vec: Vec<_> = calls.into_iter().map(|s| sha256_from_string(s)).collect();

    let v: Vec<_> = sha_vec.clone().into_iter().map(|s| convert_sha256_to_string(&s)).collect();
    println!("{v:?}");

    if let Some(detection_info) = sig_store.eval_sandboxed_file(sha_vec)? {
        //todo: do some action with detection info
        println!("{} - \"{}\",  {}", Red.paint("MALICIOUS"), file_name, detection_info);
        //println!("{}", detection_info);
    } else {
        println!("{} - \"{}\"", Green.paint("CLEAN"), file_name)
    }
    Ok(())
}

fn sandbox_path(target_path: &str) -> Result<Vec<String>, SandboxError> {
    let functions = perform_sandboxing(target_path)?;
    //println!("{functions:?}");
    //let functions: Vec<_> =
    //lines.into_iter().map(|line| get_fn_name(line)).collect();
    let mut functions: BTreeSet<String> = functions.into_iter().collect();
    functions.remove(&String::from(""));

    log::trace!("fn calls: {:?}", &functions);
    Ok(functions.into_iter().collect())
    //Ok(vec!["BlockiInput".to_string(), "Sleep".to_string(), "ShellExecuteA".to_string(), "SetCursorPos".to_string()])
}

#[allow(dead_code)]
fn get_fn_name(fn_call: String) -> String {
    //println!("{fn_call:?}");
    let Some((call, _)) = fn_call.split_once("(") else {
        return String::new();
    };
    call.to_string()
}
