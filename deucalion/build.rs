use anyhow::Result;
use vergen_git2::{Emitter, Git2};

fn main() -> Result<()> {
    if cfg!(target_os = "windows") {
        let res = winres::WindowsResource::new();
        res.compile().unwrap();
    }

    let git2 = Git2::builder().sha(true).dirty(false).build();

    Emitter::default().default_on_error().add_instructions(&git2)?.emit()?;
    Ok(())
}
