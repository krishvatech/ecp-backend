import os
import django
import sys

# -------------------------------------------------------------------------
# 1. SETUP DJANGO ENVIRONMENT
# -------------------------------------------------------------------------
# This allows the script to access your models outside of manage.py
# We assume your settings are at 'ecp_backend.settings.dev' based on your file structure.
# If you run in production, you might need to change this to 'ecp_backend.settings.prod'
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ecp_backend.settings.dev')

try:
    django.setup()
except Exception as e:
    print(f"Error setting up Django environment: {e}")
    print("Make sure you are in the root directory (same level as manage.py).")
    sys.exit(1)

# -------------------------------------------------------------------------
# 2. IMPORT MODELS
# -------------------------------------------------------------------------
from users.models import IsoLanguage

def populate():
    print("Starting language population...")

    # Format: (iso_639_1, iso_639_3, English Name, Native Name)
    languages = [
        ("ab", "abk", "Abkhazian", "аҧсуа бызшәа"),
        ("aa", "aar", "Afar", "Afaraf"),
        ("af", "afr", "Afrikaans", "Afrikaans"),
        ("ak", "aka", "Akan", "Akan"),
        ("sq", "sqi", "Albanian", "Shqip"),
        ("am", "amh", "Amharic", "አማርኛ"),
        ("ar", "ara", "Arabic", "العربية"),
        ("an", "arg", "Aragonese", "aragonés"),
        ("hy", "hye", "Armenian", "Հայերեն"),
        ("as", "asm", "Assamese", "অসমীয়া"),
        ("av", "ava", "Avaric", "авар мацӀ"),
        ("ae", "ave", "Avestan", "avesta"),
        ("ay", "aym", "Aymara", "aymar aru"),
        ("az", "aze", "Azerbaijani", "azərbaycan dili"),
        ("bm", "bam", "Bambara", "bamanankan"),
        ("ba", "bak", "Bashkir", "башҡорт теле"),
        ("eu", "eus", "Basque", "euskara"),
        ("be", "bel", "Belarusian", "беларуская мова"),
        ("bn", "ben", "Bengali", "বাংলা"),
        ("bh", "bih", "Bihari", "भोजपुरी"),
        ("bi", "bis", "Bislama", "Bislama"),
        ("bs", "bos", "Bosnian", "bosanski jezik"),
        ("br", "bre", "Breton", "brezhoneg"),
        ("bg", "bul", "Bulgarian", "български език"),
        ("my", "mya", "Burmese", "ဗမာစာ"),
        ("ca", "cat", "Catalan", "català"),
        ("ch", "cha", "Chamorro", "Chamoru"),
        ("ce", "che", "Chechen", "нохчийн мотт"),
        ("ny", "nya", "Chichewa", "chiCheŵa"),
        ("zh", "zho", "Chinese", "中文"),
        ("cv", "chv", "Chuvash", "чӑваш чӗлхи"),
        ("kw", "cor", "Cornish", "Kernewek"),
        ("co", "cos", "Corsican", "corsu"),
        ("cr", "cre", "Cree", "ᓀᐦᐃᔭᐍᐏᐣ"),
        ("hr", "hrv", "Croatian", "hrvatski jezik"),
        ("cs", "ces", "Czech", "čeština"),
        ("da", "dan", "Danish", "dansk"),
        ("dv", "div", "Divehi", "ދިވެހި"),
        ("nl", "nld", "Dutch", "Nederlands"),
        ("dz", "dzo", "Dzongkha", "རྫོང་ཁ"),
        ("en", "eng", "English", "English"),
        ("eo", "epo", "Esperanto", "Esperanto"),
        ("et", "est", "Estonian", "eesti"),
        ("ee", "ewe", "Ewe", "Eʋegbe"),
        ("fo", "fao", "Faroese", "føroyskt"),
        ("fj", "fij", "Fijian", "vosa Vakaviti"),
        ("fi", "fin", "Finnish", "suomi"),
        ("fr", "fra", "French", "français"),
        ("ff", "ful", "Fulah", "Fulfulde"),
        ("gl", "glg", "Galician", "galego"),
        ("ka", "kat", "Georgian", "ქართული"),
        ("de", "deu", "German", "Deutsch"),
        ("el", "ell", "Greek", "ελληνικά"),
        ("gn", "grn", "Guaraní", "Avañe'ẽ"),
        ("gu", "guj", "Gujarati", "ગુજરાતી"),
        ("ht", "hat", "Haitian", "Kreyòl ayisyen"),
        ("ha", "hau", "Hausa", "Hausa"),
        ("he", "heb", "Hebrew", "עברית"),
        ("hz", "her", "Herero", "Otjiherero"),
        ("hi", "hin", "Hindi", "हिन्दी"),
        ("ho", "hmo", "Hiri Motu", "Hiri Motu"),
        ("hu", "hun", "Hungarian", "magyar"),
        ("ia", "ina", "Interlingua", "Interlingua"),
        ("id", "ind", "Indonesian", "Bahasa Indonesia"),
        ("ie", "ile", "Interlingue", "Interlingue"),
        ("ga", "gle", "Irish", "Gaeilge"),
        ("ig", "ibo", "Igbo", "Asụsụ Igbo"),
        ("ik", "ipk", "Inupiaq", "Iñupiaq"),
        ("io", "ido", "Ido", "Ido"),
        ("is", "isl", "Icelandic", "Íslenska"),
        ("it", "ita", "Italian", "Italiano"),
        ("iu", "iku", "Inuktitut", "ᐃᓄᒃᑎᑐᑦ"),
        ("ja", "jpn", "Japanese", "日本語"),
        ("jv", "jav", "Javanese", "basa Jawa"),
        ("kl", "kal", "Kalaallisut", "kalaallisut"),
        ("kn", "kan", "Kannada", "ಕನ್ನಡ"),
        ("kr", "kau", "Kanuri", "Kanuri"),
        ("ks", "kas", "Kashmiri", "कश्मीरी"),
        ("kk", "kaz", "Kazakh", "қазақ тілі"),
        ("km", "khm", "Central Khmer", "ខ្មែរ"),
        ("ki", "kik", "Kikuyu", "Gĩkũyũ"),
        ("rw", "kin", "Kinyarwanda", "Ikinyarwanda"),
        ("ky", "kir", "Kirghiz", "Кыргызча"),
        ("kv", "kom", "Komi", "коми кыв"),
        ("kg", "kon", "Kongo", "Kikongo"),
        ("ko", "kor", "Korean", "한국어"),
        ("ku", "kur", "Kurdish", "Kurdî"),
        ("kj", "kua", "Kuanyama", "Kuanyama"),
        ("la", "lat", "Latin", "latine"),
        ("lb", "ltz", "Luxembourgish", "Lëtzebuergesch"),
        ("lg", "lug", "Ganda", "Luganda"),
        ("li", "lim", "Limburgan", "Limburgs"),
        ("ln", "lin", "Lingala", "Lingála"),
        ("lo", "lao", "Lao", "ພາສາລາວ"),
        ("lt", "lit", "Lithuanian", "lietuvių kalba"),
        ("lu", "lub", "Luba-Katanga", "Tshiluba"),
        ("lv", "lav", "Latvian", "latviešu valoda"),
        ("gv", "glv", "Manx", "Gaelg"),
        ("mk", "mkd", "Macedonian", "македонски јазик"),
        ("mg", "mlg", "Malagasy", "fiteny malagasy"),
        ("ms", "msa", "Malay", "Bahasa Melayu"),
        ("ml", "mal", "Malayalam", "മലയാളം"),
        ("mt", "mlt", "Maltese", "Malti"),
        ("mi", "mri", "Maori", "te reo Māori"),
        ("mr", "mar", "Marathi", "मराठी"),
        ("mh", "mah", "Marshallese", "Kajin M̧ajeļ"),
        ("mn", "mon", "Mongolian", "Монгол хэл"),
        ("na", "nau", "Nauru", "Dorerin Naoero"),
        ("nv", "nav", "Navajo", "Diné bizaad"),
        ("nd", "nde", "North Ndebele", "isiNdebele"),
        ("ne", "nep", "Nepali", "नेपाली"),
        ("ng", "ndo", "Ndonga", "Owambo"),
        ("nb", "nob", "Norwegian Bokmål", "Norsk bokmål"),
        ("nn", "nno", "Norwegian Nynorsk", "Norsk nynorsk"),
        ("no", "nor", "Norwegian", "Norsk"),
        ("ii", "iii", "Sichuan Yi", "ꆈꌠ꒿ Nuosu"),
        ("nr", "nbl", "South Ndebele", "isiNdebele"),
        ("oc", "oci", "Occitan", "occitan"),
        ("oj", "oji", "Ojibwa", "ᐊᓂᔑᓈᐯᒧᐎᓐ"),
        ("cu", "chu", "Church Slavic", "ѩзыкъ словѣньскъ"),
        ("om", "orm", "Oromo", "Afaan Oromoo"),
        ("or", "ori", "Oriya", "ଓଡ଼ିଆ"),
        ("os", "oss", "Ossetian", "ирон æвзаг"),
        ("pa", "pan", "Punjabi", "ਪੰਜਾਬੀ"),
        ("pi", "pli", "Pali", "pāli"),
        ("fa", "fas", "Persian", "فارسی"),
        ("pl", "pol", "Polish", "język polski"),
        ("ps", "pus", "Pashto", "پښتو"),
        ("pt", "por", "Portuguese", "Português"),
        ("qu", "que", "Quechua", "Runa Simi"),
        ("rm", "roh", "Romansh", "rumantsch grischun"),
        ("rn", "run", "Rundi", "Ikirundi"),
        ("ro", "ron", "Romanian", "Română"),
        ("ru", "rus", "Russian", "Русский"),
        ("sa", "san", "Sanskrit", "संस्कृतम्"),
        ("sc", "srd", "Sardinian", "sardu"),
        ("sd", "snd", "Sindhi", "सिंधी"),
        ("se", "sme", "Northern Sami", "Davvisámegiella"),
        ("sm", "smo", "Samoan", "gagana fa'a Samoa"),
        ("sg", "sag", "Sango", "yângâ tî sängö"),
        ("sr", "srp", "Serbian", "српски језик"),
        ("gd", "gla", "Gaelic", "Gàidhlig"),
        ("sn", "sna", "Shona", "chiShona"),
        ("si", "sin", "Sinhala", "සිංහල"),
        ("sk", "slk", "Slovak", "slovenčina"),
        ("sl", "slv", "Slovenian", "slovenščina"),
        ("so", "som", "Somali", "Soomaaliga"),
        ("st", "sot", "Southern Sotho", "Sesotho"),
        ("es", "spa", "Spanish", "Español"),
        ("su", "sun", "Sundanese", "Basa Sunda"),
        ("sw", "swa", "Swahili", "Kiswahili"),
        ("ss", "ssw", "Swati", "SiSwati"),
        ("sv", "swe", "Swedish", "Svenska"),
        ("ta", "tam", "Tamil", "தமிழ்"),
        ("te", "tel", "Telugu", "తెలుగు"),
        ("tg", "tgk", "Tajik", "тоҷикӣ"),
        ("th", "tha", "Thai", "ไทย"),
        ("ti", "tir", "Tigrinya", "ትግርኛ"),
        ("bo", "bod", "Tibetan", "བོད་ཡིག"),
        ("tk", "tuk", "Turkmen", "Türkmen"),
        ("tl", "tgl", "Tagalog", "Wikang Tagalog"),
        ("tn", "tsn", "Tswana", "Setswana"),
        ("to", "ton", "Tonga", "faka Tonga"),
        ("tr", "tur", "Turkish", "Türkçe"),
        ("ts", "tso", "Tsonga", "Xitsonga"),
        ("tt", "tat", "Tatar", "татар теле"),
        ("tw", "twi", "Twi", "Twi"),
        ("ty", "tah", "Tahitian", "Reo Tahiti"),
        ("ug", "uig", "Uighur", "Uyƣurqə"),
        ("uk", "ukr", "Ukrainian", "Українська"),
        ("ur", "urd", "Urdu", "اردو"),
        ("uz", "uzb", "Uzbek", "Oʻzbek"),
        ("ve", "ven", "Venda", "Tshivenḓa"),
        ("vi", "vie", "Vietnamese", "Tiếng Việt"),
        ("vo", "vol", "Volapük", "Volapük"),
        ("wa", "wln", "Walloon", "walon"),
        ("cy", "cym", "Welsh", "Cymraeg"),
        ("wo", "wol", "Wolof", "Wollof"),
        ("fy", "fry", "Western Frisian", "Frysk"),
        ("xh", "xho", "Xhosa", "isiXhosa"),
        ("yi", "yid", "Yiddish", "ייִדיש"),
        ("yo", "yor", "Yoruba", "Yorùbá"),
        ("za", "zha", "Zhuang", "Saɯ cueŋƅ"),
        ("zu", "zul", "Zulu", "isiZulu"),
    ]

    count = 0
    updated_count = 0
    
    print(f"Checking {len(languages)} languages...")

    for iso1, iso3, english, native in languages:
        obj, created = IsoLanguage.objects.get_or_create(
            iso_639_1=iso1,
            defaults={
                "iso_639_3": iso3,
                "english_name": english,
                "native_name": native
            }
        )
        
        if created:
            count += 1
        else:
            # Update existing if needed
            changed = False
            if obj.english_name != english:
                obj.english_name = english
                changed = True
            if obj.native_name != native:
                obj.native_name = native
                changed = True
            if obj.iso_639_3 != iso3:
                obj.iso_639_3 = iso3
                changed = True
            
            if changed:
                obj.save()
                updated_count += 1

    print(f"\n--- DONE ---")
    print(f"Created: {count}")
    print(f"Updated: {updated_count}")
    print(f"Total:   {IsoLanguage.objects.count()}")

if __name__ == '__main__':
    populate()