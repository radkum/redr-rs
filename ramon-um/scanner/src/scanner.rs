use std::sync::Arc;

use ansi_term::{
    Colour::{Green, Red},
    Style,
};
use common_um::redr;
use tokio::{
    sync::{
        mpsc,
        mpsc::{error::SendError, Receiver, Sender},
    },
    task::JoinHandle,
};

mod ramon_event;
mod scan_report;

pub use ramon_event::RamonEvent;
use scan_report::ScanReport;
use signatures::sig_store::SignatureStore;

use crate::{error::ScanError, scan_one_file::scan_one_file, scan_result::ScanResult};

pub struct Scanner {
    sender: Sender<RamonEvent>,
    join_handle: Option<JoinHandle<ScanReport>>,
}

impl Scanner {
    const MAX_FILE_IN_QUEUE: usize = 32;

    // to reconsider

    pub fn new(signature_store: Arc<SignatureStore>) -> Self {
        let (tx, rx) = mpsc::channel::<RamonEvent>(Self::MAX_FILE_IN_QUEUE);

        let mut scanner = Self { sender: tx, join_handle: None };

        // we want process transactions for each client separately. It allows as to parallelize work
        // and get better performance. There are disadvantages (eg. each tokio task must work till to
        // finish of program, regardless if do something or not) but it can be easy mitigated (eg.
        // add timeout to receiver and then save a state, and start only when new transaction is sent)
        scanner.run(rx, signature_store);
        scanner
    }

    fn run(&mut self, mut receiver: Receiver<RamonEvent>, signature_store: Arc<SignatureStore>) {
        let _ = ansi_term::enable_ansi_support();

        let handle = tokio::spawn(async move {
            let report = ScanReport::default();

            // messages are received till to TxAction::Close message. Then task return wallet
            while let Some(event) = receiver.recv().await {
                match event {
                    RamonEvent::CreateFile(file_info) => {
                        let file_name = file_info.1.get_name();
                        //log::debug!("Start scanning '{}' file", file_name.as_str());
                        log::warn!("Start scanning '{}' file", file_name.as_str());

                        match scan_one_file(file_info, signature_store.clone()) {
                            Ok(res) => {
                                if let ScanResult::Malicious(info, _) = res {
                                    let info_str = info.into_string();
                                    println!(
                                        "{} - {}",
                                        Red.paint("MALWARE"),
                                        Style::new().bold().paint(info_str.clone())
                                    );
                                    log::warn!(
                                        "{} - {}",
                                        Red.paint("MALWARE"),
                                        Style::new().bold().paint(info_str)
                                    );
                                } else {
                                    log::warn!("{}", Green.paint("CLEAN"),);
                                }
                            },
                            Err(err) => log::error!("{:?}", err),
                        }
                    },
                    RamonEvent::Close => receiver.close(),
                }
            }

            // Once all operations are completed, return the scan history
            report
        });

        self.join_handle = Some(handle)
    }

    pub async fn process_file(
        &self,
        file_info: redr::FileReaderAndInfo,
    ) -> Result<(), SendError<RamonEvent>> {
        self.sender.send(RamonEvent::CreateFile(file_info)).await?;
        Ok(())
    }

    pub(super) async fn scan_report(&mut self) -> Result<ScanReport, ScanError> {
        self.close().await?;
        if let Some(report) = &mut self.join_handle {
            Ok(report.await?)
        } else {
            // this should not happen. unreachable! or error?
            todo!()
            //Err(EngineError::FailedToGetWallet)
        }
    }

    pub(super) async fn close(&mut self) -> Result<(), SendError<RamonEvent>> {
        // the easiest solution to close wallet computation is to send proper message
        self.sender.send(RamonEvent::Close).await?;
        Ok(())
    }
}
