use std::{
    collections::{BTreeMap, HashMap},
    io::Read,
};

use common::utils::{convert_sha256_to_string, sha256_from_vec_of_vec, Sha256Buff};
use common_um::{detection::DetectionReport, redr};
use object::{Import, Object};

use super::{
    signature::{SigId, Signature},
    sigset_serializer::{SigSetSerializer, BIN_CONFIG},
    Description, SigName, SigSetTrait,
};
use crate::SigSetError;

type ImportInSigs = u32;

#[derive(Debug, Default)]
pub struct HeurSet {
    magic: u32,
    import_count: u32,
    import_sha_to_import_index: BTreeMap<Sha256Buff, u32>,
    imports_in_sig: Vec<ImportInSigs>,
    sig_id_to_description: HashMap<SigId, Description>,
    sig_id_to_name: HashMap<SigId, SigName>,
    sig_id_to_hash: HashMap<SigId, Vec<Sha256Buff>>,
}

impl HeurSet {
    //const BEHSET_MAGIC: [u8; 4] = [0x44, 0x35, 0x45, 0x54]; //B5ET
    pub(crate) const BEH_MAGIC_U32: u32 = 0x54453542;
    //const HEURSET_MAGIC: [u8; 4] = [0x44, 0x35, 0x45, 0x54]; //D5ET
    pub(crate) const DYN_MAGIC_U32: u32 = 0x54453544;
    //const HEURSET_MAGIC: [u8; 4] = [0x48, 0x35, 0x45, 0x54]; //H5ET
    pub(crate) const HEUR_MAGIC_U32: u32 = 0x54453548;

    fn match_(&self, sha_vec: &Vec<Sha256Buff>) -> Result<Option<Signature>, SigSetError> {
        //--------------ALGORITHM------------------
        // matching sha_vec with each signature has very low efficacy. There is better way
        // imports_in_sig field tell as which signatures has particular import. For example:
        //
        // 1) lets assume, "kernel32+sleep" after converted to sha belongs to "self.imports" on
        // first (zero index) position. Then if "kernel32+sleep" import appears in signatures
        // with id's 2,3,7,11, then first (zero index) value in "self.imports_to_sig" is
        // 1094, 0x446, 0b010001000110, because we fill "2,3,7,11" bits
        //
        // 2) next step is iterate by each import and if import exists in "imports_in_sig", then
        // clear value for import_id
        //
        // 3) then if some bit is 0 in each "imports_in_sig" value, then we found our matched signature
        // because each "import" hit clear for us one entry.
        // 4) How to find out each "sig" is hit? perform in loop bitwise or on each "import_to_sig"
        // then negate result, and then we know which sig is hit

        // 2 Sigs
        //      - 0. AAAA, [0. kernel32+sleep, 1. user32.dll+messageboxa]
        //      - 1. BBBB, [1. user32.dll+messageboxa, 2. shell32.dll+shellexecutea]
        //   \  SigID
        // ImpID     0 1 2 3
        //          __________
        //      0   |0 0 1 1   - 0b000110
        //      1   |0 0 0 0
        //      2   |0 0 0 0 0 0 0

        //todo: add algorithm example step by step
        // println!("Table");
        // for im in self.imports_in_sig.iter() {
        //     println!("{:08b}", im);
        // }
        // for a in sha_vec.iter() {
        //     println!("{}", convert_sha256_to_string(a));
        // }
        // println!("\n");
        //
        // for (a, _) in self.import_sha_to_import_index.iter() {
        //     println!("{}", convert_sha256_to_string(a));
        // }

        let sig_count = self.sig_id_to_hash.len();
        log::trace!("{:?}", self.imports_in_sig);
        let mut imports_in_sig = self.imports_in_sig.clone();
        for sha256 in sha_vec {
            let Some(import_id) = self.import_sha_to_import_index.get(sha256) else {
                continue;
            };
            log::debug!(
                "self.imports_in_sig[*import_id as usize]: {:08b}",
                self.imports_in_sig[*import_id as usize]
            );
            // if some imports hit, then we remove it from array. At the end it tell us in which
            // signature all imports were hit

            imports_in_sig[*import_id as usize] = 0;
        }

        // println!("Table");
        // for im in imports_in_sig.iter() {
        //     println!("{:08b}", im);
        // }
        // we need calculate mask. If we have 5 signatures, then mask should be
        // 0x11111111111111111111111111100000, 5 first bits empty. So to get this in first step we get:
        // 0x00000000000000000000000000011111 and then negate it
        let mut shared_imports: u32 = (1 << sig_count) - 1;
        shared_imports = !shared_imports;

        for ids in imports_in_sig {
            shared_imports |= ids;
        }

        shared_imports = !shared_imports;

        if shared_imports == 0 {
            // no match
            return Ok(None);
        }
        //some signatures are matched. Take first signature matched
        //todo: add to signatures Priority field in future
        log::trace!("matched {} sigs", shared_imports.count_ones());

        let matched_sig = shared_imports.trailing_zeros();
        log::trace!("matched_sig {} id", matched_sig);
        log::trace!("matched_sig {:?} id", self.sig_id_to_description);

        let sig = Signature::new_heur(
            self.sig_id_to_name[&matched_sig].clone(),
            self.sig_id_to_description[&matched_sig].clone(),
            self.sig_id_to_hash[&matched_sig].clone(),
            self.magic,
        );
        return Ok(Some(sig));
    }
}

fn get_characteristics(reader: &mut redr::FileReader) -> Result<Vec<Sha256Buff>, SigSetError> {
    let mut buffer = Vec::new();
    let _binary_data = reader.read_to_end(&mut buffer)?;
    let file = object::File::parse(&*buffer)?;
    get_imports(file.imports()?)
}

fn get_imports(imports: Vec<Import>) -> Result<Vec<Sha256Buff>, SigSetError> {
    const DELIMITER: u8 = b'+';

    fn import_to_sha(import: &Import) -> Result<Sha256Buff, SigSetError> {
        let sha = sha256_from_vec_of_vec(vec![
            import.library().to_ascii_lowercase(),
            vec![DELIMITER],
            import.name().to_ascii_lowercase(),
        ]);

        #[cfg(debug_assertions)]
        log::debug!(
            "import: \"{}{}{} -- {}\"",
            String::from_utf8(import.library().to_vec()).unwrap().to_lowercase(),
            DELIMITER as char,
            String::from_utf8(import.name().to_vec()).unwrap().to_lowercase(),
            convert_sha256_to_string(&sha),
        );
        Ok(sha)
    }

    imports.iter().map(|i| import_to_sha(i)).collect()
}

impl SigSetTrait for HeurSet {
    fn append_signature(&mut self, sig_id: SigId, sig: Signature) {
        let desc = sig.description();
        let name = sig.name();

        let Some(imports) = sig.data.get_sha_vec() else {
            todo!();
        };
        // 2 Sigs:
        //      - 0. AAAA, [0. kernel32+sleep, 1. user32.dll+messageboxa]
        //      - 1. BBBB, [1. user32.dll+messageboxa, 2. shell32.dll+shellexecutea]
        //      - 1. BBBB, [1. user32.dll+messageboxa, 3. user32.dll+blockinput]
        //
        //  \SigID   0 1 2 3 4 5 6 7
        // ImpID    __________
        //      0   |1 1 1 0 0 0 0 0  - 0b000111
        //      1   |1 0 0 0 0 0 0 0
        //      2   |0 1 0 0 0 0 0 0
        //      3   |0 0 1 0 0 0 0 0

        log::debug!(
            "{:?}",
            imports.iter().map(|i| convert_sha256_to_string(i)).collect::<Vec<_>>()
        );

        self.sig_id_to_hash.insert(sig_id, imports.clone());

        for import_sha in imports {
            let import_mask = 1 << sig_id; //it give as a byte number

            match self.import_sha_to_import_index.get_mut(&import_sha) {
                None => {
                    self.import_sha_to_import_index.insert(import_sha, self.import_count);
                    self.imports_in_sig.push(import_mask);
                    self.import_count += 1;
                },
                Some(import_id) => {
                    let import_ids = self.imports_in_sig.get_mut(*import_id as usize).unwrap();
                    *import_ids |= import_mask;
                },
            }
        }

        // println!("Table");
        // for im in self.imports_in_sig.iter() {
        //     println!("{:08b}", im);
        // }
        // println!("sig_id: {}, name: {}", sig_id, name);
        self.sig_id_to_name.insert(sig_id, name);
        self.sig_id_to_description.insert(sig_id, desc);
    }

    fn signatures_number(&self) -> usize {
        self.sig_id_to_name.len()
    }

    fn eval_file(
        &self,
        file: &mut redr::FileReader,
    ) -> Result<Option<DetectionReport>, SigSetError> {
        let imports_res = get_characteristics(file);
        if let Err(e) = imports_res {
            log::debug!("Not executable: {:?}", e);
            return Ok(None);
        }

        let imports = imports_res.unwrap();
        let report = self.eval_vec(imports)?;
        Ok(report)
    }

    fn eval_vec(&self, sha_vec: Vec<Sha256Buff>) -> Result<Option<DetectionReport>, SigSetError> {
        let sig_info = self.match_(&sha_vec)?;
        let report = sig_info.map(|sig| sig.into());
        Ok(report)
    }

    fn new_empty(magic: u32) -> Self
    where
        Self: Sized,
    {
        Self {
            magic,
            import_count: 0,
            import_sha_to_import_index: Default::default(),
            imports_in_sig: vec![],
            sig_id_to_description: Default::default(),
            sig_id_to_name: Default::default(),
            sig_id_to_hash: Default::default(),
        }
    }

    fn to_set_serializer(&self) -> SigSetSerializer {
        let mut ser = SigSetSerializer::new(self.magic);
        for (sig_id, imports) in self.sig_id_to_hash.iter() {
            let desc = self.sig_id_to_description[&sig_id].clone();
            let name = self.sig_id_to_name[&sig_id].clone();

            let sig = Signature::new_heur(name, desc, imports.clone(), self.magic);
            let serialized_data = bincode::serde::encode_to_vec(sig, BIN_CONFIG).unwrap();

            ser.serialize_signature(*sig_id, serialized_data);
        }
        ser
    }
}
