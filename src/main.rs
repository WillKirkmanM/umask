use clap::Parser;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    version,
    about = "Inspect the inherited Linux creation mask and calculate permission bits"
)]
struct Arguments {
    #[arg(long, value_parser = parse_octal, value_name = "OCTAL", help = "Select a calculation mask from 0000 to 0777")]
    mask: Option<u32>,

    #[arg(long, default_value = "0666", value_parser = parse_octal, value_name = "OCTAL", help = "Requested file permissions from 0000 to 0777")]
    file_mode: u32,

    #[arg(long, default_value = "0777", value_parser = parse_octal, value_name = "OCTAL", help = "Requested directory permissions from 0000 to 0777")]
    directory_mode: u32,
}

fn parse_octal(value: &str) -> Result<u32, String> {
    if value.is_empty() || !value.bytes().all(|digit| matches!(digit, b'0'..=b'7')) {
        return Err(format!(
            "'{value}' must contain only octal digits from 0 to 7"
        ));
    }

    value
        .bytes()
        .try_fold(0_u32, |mode, digit| {
            let next = mode * 8 + u32::from(digit - b'0');
            (next <= 0o777).then_some(next)
        })
        .ok_or_else(|| format!("'{value}' must be between 0000 and 0777"))
}

#[cfg(any(target_os = "linux", test))]
fn resulting_mode(requested: u32, mask: u32) -> u32 {
    requested & !mask
}

#[cfg(any(target_os = "linux", test))]
fn symbolic(mode: u32) -> String {
    [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ]
    .into_iter()
    .map(|(bit, character)| if mode & bit != 0 { character } else { '-' })
    .collect()
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn umask(mask: u32) -> u32;
}

#[cfg(target_os = "linux")]
fn inherited_mask() -> u32 {
    unsafe {
        let inherited = umask(0);
        umask(inherited);
        inherited
    }
}

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    let inherited = inherited_mask();

    let arguments = Arguments::parse();

    #[cfg(target_os = "linux")]
    {
        let selected = arguments.mask.unwrap_or(inherited);
        let file = resulting_mode(arguments.file_mode, selected);
        let directory = resulting_mode(arguments.directory_mode, selected);

        println!("Inherited mask: {inherited:04o} ({})", symbolic(inherited));
        println!("Selected mask:  {selected:04o} ({})", symbolic(selected));
        println!("File mode:      {file:04o} ({})", symbolic(file));
        println!("Directory mode: {directory:04o} ({})", symbolic(directory));
        println!(
            "Mask symbols show bits removed; calculated modes exclude effects from default ACLs."
        );
        ExitCode::SUCCESS
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = arguments;
        eprintln!("error: unsupported platform: this command requires Linux umask");
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octal_parser_accepts_boundaries_and_rejects_invalid_values() {
        assert_eq!(parse_octal("0000"), Ok(0));
        assert_eq!(parse_octal("0777"), Ok(0o777));
        assert_eq!(parse_octal("27"), Ok(0o27));
        assert_eq!(parse_octal("00000000000000000027"), Ok(0o27));
        for value in [
            "",
            "0089",
            "1000",
            "-1",
            "+27",
            "0o27",
            " 027",
            "77777777777777777777",
            "99999999999999999999",
        ] {
            assert!(parse_octal(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn mask_removes_bits_without_adding_permissions() {
        assert_eq!(resulting_mode(0o666, 0o027), 0o640);
        assert_eq!(resulting_mode(0o777, 0o027), 0o750);
        assert_eq!(resulting_mode(0o400, 0), 0o400);
        assert_eq!(resulting_mode(0o777, 0o777), 0);
        assert_eq!(resulting_mode(0, 0o027), 0);
    }

    #[test]
    fn symbolic_permissions_preserve_bit_positions() {
        assert_eq!(symbolic(0), "---------");
        assert_eq!(symbolic(0o777), "rwxrwxrwx");
        assert_eq!(symbolic(0o640), "rw-r-----");
        assert_eq!(symbolic(0o750), "rwxr-x---");
        assert_eq!(symbolic(0o027), "----w-rwx");
    }

    #[test]
    fn command_line_validates_modes_and_supplies_defaults() {
        let arguments = Arguments::try_parse_from(["umask"]).unwrap();
        assert_eq!(arguments.mask, None);
        assert_eq!(arguments.file_mode, 0o666);
        assert_eq!(arguments.directory_mode, 0o777);

        let arguments = Arguments::try_parse_from([
            "umask",
            "--mask",
            "0027",
            "--file-mode",
            "0666",
            "--directory-mode",
            "0777",
        ])
        .unwrap();
        assert_eq!(arguments.mask, Some(0o027));
        assert_eq!(arguments.file_mode, 0o666);
        assert_eq!(arguments.directory_mode, 0o777);
        assert!(Arguments::try_parse_from(["umask", "--mask", "0089"]).is_err());
        assert!(Arguments::try_parse_from(["umask", "--file-mode", "1000"]).is_err());
        assert!(Arguments::try_parse_from(["umask", "--directory-mode"]).is_err());
    }

    #[test]
    fn help_and_version_are_available_on_every_platform() {
        for flag in ["--help", "--version"] {
            let error = Arguments::try_parse_from(["umask", flag]).err().unwrap();
            assert_eq!(error.exit_code(), 0);
            assert!(matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ));
        }
    }
}
