import streamlit as st
import whois
import requests
from ipwhois import IPWhois
import socket
import datetime
from urllib.parse import urljoin
import base64

def tool1():
    st.title("🔍 URL Analizi")

    url = st.text_input("Kısaltılmış URL gir:")

    if st.button("Analizi Başlat"):
        if not url:
            st.warning("Lütfen bir URL girin.")
            return

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        try:
            response = requests.get(url, headers=headers, allow_redirects=True, timeout=10)
            final_url = response.url
            status_code = response.status_code

            st.success(f"Bu URL şuraya yönlendiriyor: {final_url}")
            st.write("Status Code:", status_code)

            if response.history:
                st.info("Yönlendirme zinciri:")
                for i, resp in enumerate(response.history, start=1):
                    st.write(f"{i}. {resp.status_code} → {resp.url}")
        except requests.exceptions.RequestException as e:
            st.error(f"URL çözümlenemedi: {e}")

def tool2():
    st.title("🧪 Fuzz Testi")
    target = st.text_input("Hedef URL gir (Örnek: https://orneksite.com/):")
    wordlist_text = st.text_area("Wordlist gir (her satıra bir kelime):")
    if st.button("Testi Başlat"):
        if not target or not wordlist_text:
            st.warning("Hedef ve wordlist gereklidir!")
            return
        wordlist = [line.strip() for line in wordlist_text.splitlines() if line.strip()]
        st.info(f"{len(wordlist)} kelime ile fuzzing başlatılıyor...")
        results = []
        progress_text = st.empty()
        for idx, word in enumerate(wordlist, start=1):
            url = urljoin(target, word)
            try:
                response = requests.get(url, timeout=5)
                results.append({"URL": url, "Status": response.status_code})
            except requests.exceptions.RequestException as e:
                results.append({"URL": url, "Status": f"Hata: {e}"})
            progress_text.text(f"{idx}/{len(wordlist)} tarandı...")
        st.success("Fuzzing tamamlandı!")
        st.subheader("Sonuçlar")
        st.table(results)

def tool3():
    st.title("🌐 Whois Analizi")

    query = st.text_input("Domain veya IP girin (Örnek: orneksite.com veya 8.8.8.8):")

    if st.button("Sorguyu Başlat"):
        if not query:
            st.warning("Lütfen bir domain veya IP girin!")
            return
        
        # Domain mi yoksa IP mi kontrol et
        try:
            socket.inet_aton(query)
            is_ip = True
        except:
            is_ip = False

        if is_ip:
            st.info(f"{query} bir IP adresi olarak algılandı. IP bilgileri alınıyor...")
            try:
                ip_info = IPWhois(query).lookup_rdap()
                st.subheader("IP Whois Bilgileri")
                st.write(f"IP Adresi: {query}")
                st.write(f"Network: {ip_info.get('network', {}).get('name', 'Bilinmiyor')}")
                st.write(f"Handle: {ip_info.get('network', {}).get('handle', 'Bilinmiyor')}")
                st.write(f"Country: {ip_info.get('network', {}).get('country', 'Bilinmiyor')}")
                st.write(f"Organization: {ip_info.get('network', {}).get('remarks', [{'description':'Bilinmiyor'}])[0]['description']}")
                st.write(f"CIDR: {ip_info.get('network', {}).get('cidr', 'Bilinmiyor')}")
                st.write(f"Creation Date: {ip_info.get('network', {}).get('start_address', 'Bilinmiyor')}")
            except Exception as e:
                st.error(f"IP bilgisi alınamadı: {e}")
        else:
            st.info(f"{query} bir domain olarak algılandı. Whois sorgusu yapılıyor...")
            try:
                domain_info = whois.whois(query)
                st.subheader("Domain Whois Bilgileri")
                st.write(f"Domain: {domain_info.domain_name}")
                st.write(f"Registrar: {domain_info.registrar}")
                st.write(f"Kayıt Tarihi: {domain_info.creation_date}")
                st.write(f"Güncelleme Tarihi: {domain_info.updated_date}")
                st.write(f"Sona Erme Tarihi: {domain_info.expiration_date}")
                st.write(f"Name Servers: {domain_info.name_servers}")
                st.write(f"Status: {domain_info.status}")
                st.write(f"Emails: {domain_info.emails}")
            except Exception as e:
                st.error(f"Domain bilgisi alınamadı: {e}")

def tool4():
    st.title("📡 Port Tarama")
    target = st.text_input("Hedef IP adresini veya domainini gir:")
    ports_text = st.text_input("Port aralığı gir (Örnek: 20-1024):", value="20-1024")
    if st.button("Taramayı Başlat"):
        if not target:
            st.warning("Lütfen hedef girin.")
            return
        try:
            start_port, end_port = map(int, ports_text.split('-'))
        except:
            st.error("Port aralığı hatalı!")
            return
        st.info(f"{target} üzerinde port taraması başlatılıyor...")
        open_ports = []
        progress_text = st.empty()
        total_ports = end_port - start_port + 1
        for idx, port in enumerate(range(start_port, end_port+1), start=1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
            progress_text.text(f"{idx}/{total_ports} port tarandı...")
        st.success("Taramay tamamlandı!")
        if open_ports:
            st.subheader("Açık Portlar:")
            st.write(open_ports)
        else:
            st.subheader("Açık port bulunamadı.")

def tool5():
    st.title("🛡️ Subdomain Tarama")

    domain = st.text_input("Hedef domainini gir (Örnek: orneksite.com):")
    wordlist_text = st.text_area("Subdomain wordlist gir (Her satıra bir kelime; Örnek: www, mail, api):",
                                 value="www\nmail\napi\ndev\nblog")

    if st.button("Taramayı Başlat"):
        if not domain:
            st.warning("Lütfen bir domain girin.")
            return
        if not wordlist_text:
            st.warning("Lütfen bir wordlist girin veya örnekleri kullanın.")
            return

        wordlist = [line.strip() for line in wordlist_text.splitlines() if line.strip()]
        st.info(f"{len(wordlist)} adet subdomain ile tarama başlatılıyor...")

        found = []
        progress_text = st.empty()

        for idx, sub in enumerate(wordlist, start=1):
            url = f"http://{sub}.{domain}"
            try:
                response = requests.get(url, timeout=3)
                if response.status_code < 400:
                    found.append({"Subdomain": url, "Status": response.status_code})
            except requests.exceptions.RequestException:
                pass
            progress_text.text(f"{idx}/{len(wordlist)} tarandı...")

        st.success("Taramay tamamlandı!")
        if found:
            st.subheader("Bulunan Subdomainler:")
            st.table(found)
        else:
            st.info("Hiçbir subdomain bulunamadı.")

def main_screen():
    st.markdown("<h1 style='text-align: center;'>WedSec Mini</h1>", unsafe_allow_html=True)
    
    # Logo yükleme
    try:
        file_ = open("WedSec Mini.png", "rb")
        contents = file_.read()
        file_.close()
        data_url = base64.b64encode(contents).decode("utf-8")

        st.markdown(
            f"""
            <div style='text-align: center; margin-bottom:20px;'>
                <img src="data:image/png;base64,{data_url}" width="200">
            </div>
            """,
            unsafe_allow_html=True
        )
    except:
        st.warning("Logo bulunamadı. 'WedSec Mini.png' dosyasını eklemeyi unutmayın.")

    # Hoş geldiniz
    st.markdown(
        """
        <div style='text-align: center; font-size: 18px; line-height: 1.6; margin-bottom: 40px;'>
            <h2>💻 WedSec Mini'ye Hoş Geldiniz</h2>
            <p>
            <b>WedSec Mini</b>, siber güvenlik alanında sık kullanılan temel araçları tek bir yerde sunmak için geliştirilmiş
            pratik ve kullanıcı dostu bir uygulamadır.  
            Güvenlik testleri, bilgi toplama ve analiz süreçlerinde ihtiyaç duyabileceğiniz birçok özelliği barındırır.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Araçlar - kart görünümü
    st.markdown(
        """
        <h3 style="text-align:center;">🚀 Hangi Araçlar Mevcut?</h3>
        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-top: 20px;">
            <div style="padding: 15px; border: 1px solid #ddd; border-radius: 12px; background: #f9f9f9; box-shadow: 2px 2px 8px rgba(0,0,0,0.05);">
                <b>🔍 URL Analizi</b><br>
                Kısaltılmış bağlantıların hangi adrese yönlendirdiğini öğrenin ve durum kodlarını görün.
            </div>
            <div style="padding: 15px; border: 1px solid #ddd; border-radius: 12px; background: #f9f9f9; box-shadow: 2px 2px 8px rgba(0,0,0,0.05);">
                <b>🧪 Fuzz Testi</b><br>
                Hedef web sitesinde dizin ve dosya keşfi yaparak olası güvenlik açıklarını araştırın.
            </div>
            <div style="padding: 15px; border: 1px solid #ddd; border-radius: 12px; background: #f9f9f9; box-shadow: 2px 2px 8px rgba(0,0,0,0.05);">
                <b>🌐 Whois Analizi</b><br>
                Domain ve IP adreslerine ait kayıtlı bilgileri sorgulayarak organizasyon, ülke, tarih ve registrar detaylarını öğrenin.
            </div>
            <div style="padding: 15px; border: 1px solid #ddd; border-radius: 12px; background: #f9f9f9; box-shadow: 2px 2px 8px rgba(0,0,0,0.05);">
                <b>📡 Port Tarama</b><br>
                Belirlenen IP veya domain üzerinde port taraması yaparak açık portları tespit edin.
            </div>
            <div style="padding: 15px; border: 1px solid #ddd; border-radius: 12px; background: #f9f9f9; box-shadow: 2px 2px 8px rgba(0,0,0,0.05);">
                <b>🛡️ Subdomain Tarama</b><br>
                Belirlenen domain üzerinde subdomain araması yaparak ek servis ve giriş noktalarını keşfedin.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Neden WedSec Mini
    st.markdown(
        """
        <div style='margin-top:40px; font-size:16px; line-height:1.6;'>
            <h3>🎯 Neden WedSec Mini?</h3>
            WedSec Mini, karmaşık güvenlik test araçlarını tek ekranda toplayarak öğrenme sürecini hızlandırır 
            ve pratik bir şekilde analiz yapmanızı sağlar.  
            Öğrenciler, güvenlik meraklıları ve başlangıç seviyesindeki pentesterlar için idealdir.  
            Profesyoneller içinse hızlı testler yapmaya imkân tanıyan hafif bir alternatiftir.
        </div>
        """,
        unsafe_allow_html=True
    )

    # Kullanım Notu
    st.markdown(
        """
        <div style='margin-top:40px; padding:15px; border-radius:10px; background:#fff3f3; border:1px solid #ffcccc;'>
            <h3>⚠️ Kullanım Notu</h3>
            Bu araç yalnızca <b>eğitim ve test amaçlı</b> geliştirilmiştir.  
            Kendi sistemleriniz dışında kullanmadan önce ilgili izinleri almanız gerekmektedir.  
            Yetkisiz kullanım <b>yasal sorunlara yol açabilir</b>.
        </div>
        <div style='text-align:center; margin-top:20px; font-size:18px;'>
            🔧 Sol menüden bir araç seçerek hemen başlayabilirsiniz.
        </div>
        """,
        unsafe_allow_html=True
    )

st.set_page_config(page_title="WedSec Mini", page_icon="WedSec Mini.png", layout="wide")
st.sidebar.title("Kontrol Paneli")

if "selected_tool" not in st.session_state:
    st.session_state.selected_tool = "main"

if st.sidebar.button("🏠 Ana Ekran"):
    st.session_state.selected_tool = "main"
if st.sidebar.button("🔍 URL Analizi"):
    st.session_state.selected_tool = "tool1"
if st.sidebar.button("🧪 Fuzz Testi"):
    st.session_state.selected_tool = "tool2"
if st.sidebar.button("🌐 Whois Analizi"):
    st.session_state.selected_tool = "tool3"
if st.sidebar.button("📡 Port Tarama"):
    st.session_state.selected_tool = "tool4"
if st.sidebar.button("🛡️ Subdomain Tarama"):
    st.session_state.selected_tool = "tool5"

if st.session_state.selected_tool == "main":
    main_screen()
elif st.session_state.selected_tool == "tool1":
    tool1()
elif st.session_state.selected_tool == "tool2":
    tool2()
elif st.session_state.selected_tool == "tool3":
    tool3()
elif st.session_state.selected_tool == "tool4":
    tool4()
elif st.session_state.selected_tool == "tool5":
    tool5()
