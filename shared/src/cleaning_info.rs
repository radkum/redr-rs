use crate::event::Pid;

pub trait CleaningInfoTrait {
    fn get_pid(&self) -> Pid;
}
