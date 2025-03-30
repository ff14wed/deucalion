use anyhow::Result;
use vergen_git2::{Emitter, Git2Builder};

fn main() -> Result<()> {
    if cfg!(target_os = "windows") {
        let res = winres::WindowsResource::new();
        res.compile().unwrap();
    }

    let git2 = Git2Builder::default().sha(true).dirty(false).build()?;

    Emitter::default().add_instructions(&git2)?.emit()?;
    Ok(())
}
