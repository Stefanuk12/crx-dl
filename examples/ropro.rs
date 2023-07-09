// Dependencies
use std::{fs::File, io::Write};
use crx_dl::{ChromeCRXQuery, crx_to_zip};

/// The id of the extension we want to download.
const EXT_ID: &str = "adbacgifemdbhdkfppmeilbgppmhaobf";

/// Entrypoint.
fn main() -> Result<(), std::io::Error> {
    // Download the extension
    let mut crx_query = ChromeCRXQuery::default();
    crx_query.x = EXT_ID;
    let extension_crx = crx_query.download_blocking().unwrap();

    // Convert it to .zip
    let crx_zip = crx_to_zip(extension_crx, None)?;

    // Output to file
    let mut file_out = File::create(format!("{}.zip", EXT_ID))?;
    file_out.write_all(&crx_zip)?;

    // Success
    Ok(())
}