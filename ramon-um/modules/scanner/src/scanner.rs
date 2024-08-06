use tokio::{
    sync::{
        mpsc,
        mpsc::{error::SendError, Receiver, Sender},
    },
    task::JoinHandle,
};
use common_um::redr;
use ansi_term::Colour::Red;
use common_um::detection::DetectionReport;

mod scan_report;
use scan_report::ScanReport;
use signatures::error::SigSetError;
use signatures::sig_store::SignatureStore;
use crate::error::ScanError;

pub struct Scanner {
    sender: Sender<redr::FileReaderAndInfo>,
    join_handle: Option<JoinHandle<ScanReport>>,
}

impl Scanner {
    const MAX_FILE_IN_QUEUE: usize = 32; // to reconsider

    pub fn new(signature_store: SignatureStore) -> Self {
        let (tx, rx) = mpsc::channel::<redr::FileReaderAndInfo>(Self::MAX_FILE_IN_QUEUE);

        let mut scanner = Self { sender: tx, join_handle: None };

        // we want process transactions for each client separately. It allows as to parallelize work
        // and get better performance. There are disadvantages (eg. each tokio task must work till to
        // finish of program, regardless if do something or not) but it can be easy mitigated (eg.
        // add timeout to receiver and then save a state, and start only when new transaction is sent)
        scanner.run(rx, signature_store);
        scanner
    }

    fn run(&mut self, mut receiver: Receiver<redr::FileReaderAndInfo>, signature_store: SignatureStore) {
        let handle = tokio::spawn(async move {
            let mut report = ScanReport::default();

            // messages are received till to TxAction::Close message. Then task return wallet
            while let Some(file_info) = receiver.recv().await {
                let (mut reader, file_scan_info) = file_info;

                let file_name = file_scan_info.get_name();
                log::debug!("Start scanning '{}' file", file_name.as_str());

                let scan_result = match signature_store.eval_file(&mut reader) {
                    Ok(report) => report,
                    Err(err) => {
                        log::error!("{:?}", err);
                        continue;
                    },
                };

                if let Some(detection_info) = scan_result {
                    //todo: do some action with detection info
                    println!(
                        "{} - {}",
                        Red.paint("MALICIOUS"),
                        file_scan_info.get_malware_info(detection_info)
                    );

                    report.push_malicious(file_name.clone())
                } else {
                    report.push_clean(file_name.clone())
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
    ) -> Result<(), SendError<redr::FileReaderAndInfo>> {
        self.sender.send(file_info).await?;
        Ok(())
    }

    pub(super) async fn scan_report(&mut self) -> Result<ScanReport, ScanError> {
        //self.close().await?;
        if let Some(report) = &mut self.join_handle {
            Ok(report.await?)
        } else {
            // this should not happen. unreachable! or error?
            todo!()
            //Err(EngineError::FailedToGetWallet)
        }
    }

    // pub(super) async fn close(&mut self) -> Result<(), SendError<TransactionInfo>> {
    //     // the easiest solution to close wallet computation is to send proper message
    //     self.process_transaction(TransactionInfo::close()).await?;
    //     Ok(())
    // }
}
