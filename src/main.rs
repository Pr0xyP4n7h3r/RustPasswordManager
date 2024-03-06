use std::fs::{self, File};
use std::path::Path;
use std::io::{self, Read};
use std::io::Write; 
use openssl::symm::{Cipher, Crypter, Mode};

extern crate openssl;
struct Acc {
    app: String,
    username: String,
    password: String,    
}

fn encrypt(password: &str, key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_256_cbc();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
    let max_output_len = password.len() + cipher.block_size();
    let mut encryptedData = vec![0u8; max_output_len];

    let count = encrypter
        .update(password.as_bytes(), &mut encryptedData)
        .unwrap();

    let finalCount = encrypter.finalize(&mut &mut encryptedData[count..]).unwrap();
    encryptedData.truncate(count + finalCount);

    encryptedData
}

fn decrypt(encryptedData: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_256_cbc();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
    decrypter.pad(true);
    let max_output_len = encryptedData.len() + cipher.block_size();
    let mut decryptedData = vec![0u8; max_output_len];

    let count = decrypter
        .update(&encryptedData, &mut decryptedData)
        .unwrap();

    let finalCount = decrypter.finalize(&mut decryptedData[count..]).unwrap();
    decryptedData.truncate(count + finalCount);

    decryptedData
}

fn register(key: &[u8;  32]) {
    let mut acc = Acc {
	app: String::new(),
        username: String::new(),
        password: String::new(),
    };

    println!("Unesi username: ");
    io::stdin()
        .read_line(&mut acc.username)
        .expect("Error");

    let fileName = format!("{}.txt", acc.username.trim());
    let mut file = File::create(&fileName).unwrap();

    println!("Unesi password: ");
    io::stdin()
        .read_line(&mut acc.password)
        .expect("Error");

    let encryptedData = encrypt(&acc.password, key);

    if let Err(e) = file.write_all(&encryptedData) {
        eprintln!("Greška prilikom pisanja u listi: {}", e);
    } else {
        println!("Account je uspešno sačuvan");
    }

}

struct App {
    app: String,
    username: String,
    password: String,
}

fn create(key: &[u8;  32]) {
    let mut acc = App {
        app: String::new(),
        username: String::new(),
        password: String::new(),
    };

    println!("Unesi ime aplikacije: ");
    io::stdin()
        .read_line(&mut acc.app)
        .expect("Error");

    let folderName = acc.app.trim();
    let folderPath = format!("./{}", folderName);

    if !Path::new(&folderPath).exists() {
        fs::create_dir(&folderPath).expect("Error creating folder");
    }

    println!("Unesi username: ");
    io::stdin()
        .read_line(&mut acc.username)
        .expect("Error");

    let fileName = format!("{}/{}.txt", folderName, acc.username.trim());
    let mut file = File::create(&fileName).expect("Error creating file");

    println!("Unesi password: ");
    io::stdin()
        .read_line(&mut acc.password)
        .expect("Error");

    let encryptedData = encrypt(&acc.password, key);

    if let Err(e) = file.write_all(&encryptedData) {
        eprintln!("Greška prilikom pisanja u listi: {}", e);
    } else {
        println!("Account je uspešno sačuvan za aplikaciji: {}", folderName);
    }
}

fn get(key: &[u8; 32]) {
    println!("Unesi ime aplikacije: ");
    let mut appName = String::new();
    io::stdin()
        .read_line(&mut appName)
        .expect("Error");

    let appFolder = format!("./{}", appName.trim());

    if !Path::new(&appFolder).exists() {
        println!("Aplikacija ne postoji ili nema naloge za tu aplikaciju.");
    } else {
        println!("Nalozi za aplikaciju '{}' su:", appName.trim());
        let entries = fs::read_dir(&appFolder).expect("Error");
        for entry in entries {
            if let Ok(entry) = entry {
                if let Some(fileName) = entry.file_name().to_str() {
                    if fileName.ends_with(".txt") {
                        println!("{}", fileName);
                    }
                }
            }
        }
    }
}


fn login(key: &[u8; 32]) {
    let mut usernameInput =  String::new();
    let mut passwordInput =  String::new();
    let mut pokusaji = 0;

    loop {
        println!("Unesi username: ");
        io::stdin()
            .read_line(&mut usernameInput)
            .expect("Error");

        let mut fileInput = format!("{}.txt", usernameInput.trim());
        
        if Path::new(&fileInput).exists() {
            loop {
                println!("Unesi password: ");
                io::stdin()
                    .read_line(&mut passwordInput)
                    .expect("Error");

                let mut file = File::open(&fileInput).unwrap();

                let mut encryptedData = Vec::new();

                file.read_to_end(&mut encryptedData).unwrap();

                if passwordInput.trim() == String::from_utf8(decrypt(&encryptedData, key)).unwrap().trim() {
                    println!("Ekrup se ulogovao!");
                    loop {
                        println!("1. Create");
                        println!("2. Get");
    
                        let mut optionInput = String::new();
                        io::stdin()
                            .read_line(&mut optionInput)
                            .expect("Error");
    
                        match &optionInput.trim() {
                            &"1" => create(key),
                            &"2" => get(key),
                            _ => println!("Nepoznata opcija!"),
                        }
                    }
                } else {
                    println!("Pokusaj ponovo!");
                    pokusaji += 1;
                    
                }

                passwordInput.clear();
            }
            break;
        } else {
            println!("Ekrupe pokusaj ponovo!");
            pokusaji += 1;
        }
    
        if pokusaji == 5 {
            println!("Ekrupe pokusaj kasnije...");
            break;
        }

        usernameInput.clear();
    }
}

fn main() {
    let mut numberInput = String::new();
    let mut key: [u8; 32] = [0; 32];
    let mut encryptKey = String::new();

    println!("Unesi key od 32 karaktera: ");
    io::stdin()
        .read_line(&mut encryptKey)
        .expect("Error");

    key.copy_from_slice(encryptKey.trim().as_bytes());

    println!("Za pristup registraciji pritisine taster 1");
    println!("Za pristup loginovanju pritisine taster 2");

    io::stdin()
        .read_line(&mut numberInput)
        .expect("Error");

    let brojInput = match numberInput.trim().parse::<u32>() {
        Ok(value) => value,
        Err(_) => {
            println!("Ekrup nije uneo broja kako treba!");
            return;
        }
    };

    if brojInput == 1 {
        register(&key);
    } else if brojInput == 2 {
        login(&key);
    } else {
        println!("Ekrup je nasao problem")
    } 
}

