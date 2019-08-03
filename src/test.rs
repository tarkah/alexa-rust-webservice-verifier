fn main() {
    if let Err(e) = run() {
        println!("ERROR: {}", e);

        for cause in e.iter_causes() {
            println!("Caused by: {}", cause);
        }

        std::process::exit(1);
    }
}

fn run() -> Result<(), failure::Error> {
    let mut verifier = verifier::RequestVerifier::new();
    let signature = "OJCN0G2dcmjtZxr2RGUh/63FKRfCv9CufT4w1aqCHhABCyUkOH8Pqal35WBiLTVi/mD+pC8yTZR5puw70LOAQcO+YhZ+rpfX3n2Op70+cLmVqHbtVz+8tOM4U38wSyPVIHjyQwK9Kki+DtMtRzaKrPSGgKyqyy71NwWyeIKn/AuyMniR+DFOzAqm9h5i5wI/Gh4mktbvRAAGkG0kBosswQa++W5Ewmi72zU/j28JPhvyNZrYB6NQW8UMQ3VKzneL6tRZv8JDNk7xDKviTTvKfMDYiVLFP0DIYIdsO79FNc5BS7f1xbXnn/LgpfRqmlvu2araY8yiICEGwCK9OhLn/Q==";
    let signature_url =
        "https://s3.amazonaws.com/././../../echo.api/../../echo.api/../echo.api/./././echo-api-cert-7.pem";
    verifier.verify(signature_url.to_string(), signature.to_string())?;
    Ok(())
}
