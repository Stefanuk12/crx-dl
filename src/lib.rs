// Dependencies
use std::io::{Cursor, BufReader, Read, SeekFrom, Seek, ErrorKind, Error};
use base64::{engine::general_purpose, Engine as _};

/// Possible product ids.
#[derive(Debug, Clone, strum::Display, strum::EnumString)]
pub enum ProductId {
    #[strum(serialize="chromecrx")]
    ChromeCRX,
    #[strum(serialize="chromiumcrx")]
    ChromiumCRX,
}

/// Types of operating systems.
#[derive(Debug, Clone, strum::Display, strum::EnumString)]
pub enum OperatingSystem {
    #[strum(serialize="win")]
    Windows,
    #[strum(serialize="linux")]
    Linux,
    #[strum(serialize="mac")]
    MacOS,
    #[strum(serialize="cros")]
    ChromeOS,
    #[strum(serialize="openbsd")]
    BSD,
    #[strum(serialize="android")]
    Android
}

/// Types of architecture.
#[derive(Debug, Clone, strum::Display, strum::EnumString)]
pub enum Architecture {
    #[strum(serialize="arm")]
    ARM,
    #[strum(serialize="x86-32")]
    Intel32,
    #[strum(serialize="x86-64")]
    AMD64,
}

/// The query parameters sent to <https://clients2.google.com/service/update2/crx> for Chrome.
pub struct ChromeCRXQuery<'a> {
    pub response: &'a str,
    pub os: OperatingSystem,
    pub arch: Architecture,
    pub os_arch: Architecture,
    pub nacl_arch: Architecture,
    /// Omitting this value is allowed, but add it just in case.
    pub prod: ProductId,
    /// Channel is "unknown" on Chromium on ArchLinux, so using "unknown" will probably be fine for everyone.
    pub prodchannel: &'a str,
    /// As of July, the Chrome Web Store sends 204 responses to user agents when their
    /// Chrome/Chromium version is older than version 31.0.1609.0
    pub prodversion: &'a str,
    pub acceptformat: &'a str,
    pub x: &'a str
}
impl ChromeCRXQuery<'_> {
    /// Converts to a format where it can be used by reqwest.
    pub fn to_vec(&self) -> Vec<(String, String)> {
        vec![
            ("response", self.response),
            ("os", &self.os.to_string()),
            ("arch", &self.arch.to_string()),
            ("os_arch", &self.os_arch.to_string()),
            ("nacl_arch", &self.nacl_arch.to_string()),
            ("prod", &self.prod.to_string()),
            ("prodchannel", self.prodchannel),
            ("prodversion", self.prodversion),
            ("acceptformat", self.acceptformat),
            ("x", &format!("id={}&uc", self.x))
        ]
        .iter()
        .map(|x| (x.0.to_string(), x.1.to_string()))
        .collect()
    }

    /// Downloads the extension.
    /// 
    /// For a blocking version, use [`download_blocking`].
    pub async fn download(&self) -> Result<Vec<u8>, reqwest::Error> {
        Ok(
            reqwest::Client::new()
                .get("https://clients2.google.com/service/update2/crx")
                .query(&self.to_vec())
                .send()
                .await?
                .bytes()
                .await?
                .to_vec()
        )
    }

    /// Downloads the extension.
    /// 
    /// For a async version, use [`download`].
    pub fn download_blocking(&self) -> Result<Vec<u8>, reqwest::Error> {
        Ok(
            reqwest::blocking::Client::new()
                .get("https://clients2.google.com/service/update2/crx")
                .query(&self.to_vec())
                .send()?
                .bytes()?
                .to_vec()
        )
    }
}
impl Default for ChromeCRXQuery<'_> {
    fn default() -> Self {
        Self { 
            response: "redirect",
            os: OperatingSystem::Windows,
            arch: Architecture::AMD64,
            os_arch: Architecture::AMD64,
            nacl_arch: Architecture::AMD64,
            prod: ProductId::ChromeCRX,
            prodchannel: "unknown",
            prodversion: "9999.0.9999.0",
            acceptformat: "crx2,crx3",
            x: "" 
        }
    }
}

/// Not complete!
/// 
/// Grabs the public key of a CRX from protobuf, returned as base64 encoded.
/// It's assumed the reader is correctly positioned.
/// 
/// View <https://github.com/Rob--W/crxviewer/blob/master/src/lib/crx-to-zip.js#L109> for an implementation.
/// 
/// Please contribute if you want this fixed!
pub fn public_key_protobuf(mut reader: BufReader<Cursor<Vec<u8>>>, end_seek: u64) -> Result<String, Error> {
    todo!()
}

/// Converts CRX to ZIP.
/// 
/// Set `previous_public_key` to `None. It's used for checking when doing nested CRX files.
/// 
/// Credits <https://github.com/Rob--W/crxviewer/blob/master/src/lib/crx-to-zip.js#L16>
pub fn crx_to_zip(crx: Vec<u8>, previous_public_key: Option<String>) -> Result<Vec<u8>, Error> {
    let mut reader = BufReader::new(Cursor::new(crx));

    // Ensure is a CRX file
    let mut magic_number = [0; 4];
    reader.read_exact(&mut magic_number)?;
    if String::from_utf8_lossy(&magic_number) != "Cr24" {
        return Err(Error::new(ErrorKind::InvalidData, "input is not a crx file"));
    }

    // Read the version
    let mut version = [0; 4];
    reader.read_exact(&mut version)?;
    let version = u32::from_le_bytes(version);

    // The next four bytes can either be one of the following depending on `version`
    // public_key_length -> version 2
    // crx3_header_length -> version 3
    let mut next_four_buf = [0; 4];
    reader.read_exact(&mut next_four_buf)?;
    let next_four = u32::from_le_bytes(next_four_buf);

    // Special things for each version
    let (zip_start_offset, public_key_b64) = match version {
        2 => {        
            // Read the signature length
            let mut signature_key_length = [0u8; 4];
            reader.read_exact(&mut signature_key_length)?;
            let signature_key_length = u32::from_le_bytes(signature_key_length);

            // Calculate the zip start offset
            let zip_start_offset = 16 + next_four + signature_key_length;

            // Figure out the public key (we should be at 16 at this stage)
            let mut pk_buf = [0u8; 4];
            reader.read_exact(&mut pk_buf)?;
            let public_key_b64 = general_purpose::STANDARD.encode(pk_buf);

            // Done
            (zip_start_offset, public_key_b64)
        },
        3 => {
            // Calculate the zip start offset
            let zip_start_offset = 12 + next_four;

            // Figure out the public key (we should be at 12 at this stage)
            // Does not work, empty string as placeholder
            let public_key_b64 = String::from("");//public_key_protobuf(reader, zip_start_offset.into())?;

            // Done
            (zip_start_offset, public_key_b64)
        },
        _ => return Err(Error::new(ErrorKind::InvalidData, "invalid crx version"))
    };

    // Additional checks for addons.opera.com
    // They create CRX3 files by prepending the CRX3 header to the CRX2 data.
    let mut opera_buf = [0; 4];
    reader.read_exact(&mut opera_buf)?;
    if version == 3 && String::from_utf8_lossy(&opera_buf) == "Cr24" {
        // Checking if we got a public key mismatch
        if previous_public_key.is_some() && previous_public_key.unwrap() != public_key_b64 {
            println!("Nested CRX: pubkey mismatch; found {}", public_key_b64);
        }

        // Repeat the process
        let mut out: Vec<u8> = Vec::new();
        reader.read_to_end(&mut out)?;
        crx_to_zip(out, Some(public_key_b64))?;
    }

    // Done
    reader.seek(SeekFrom::Start(zip_start_offset.into()))?;
    let mut out: Vec<u8> = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}