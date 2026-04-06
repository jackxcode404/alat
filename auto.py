import requests
import random
import time
import json
from fake_useragent import UserAgent
from urllib.parse import urlparse
import threading

class WebsiteAutoViews:
    def __init__(self, target_url, views_count=1000):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.views_count = views_count
        self.ua = UserAgent()
        self.successful_views = 0
        self.session = requests.Session()
        
        # Website-specific settings
        self.website_configs = {
            'youtube.com': self.youtube_config,
            'youtu.be': self.youtube_config,
            'tiktok.com': self.tiktok_config,
            'instagram.com': self.instagram_config,
            'facebook.com': self.facebook_config,
        }
    
    def get_config(self):
        """Get config berdasarkan domain"""
        for domain, config in self.website_configs.items():
            if domain in self.domain:
                return config()
        return self.default_config()
    
    def default_config(self):
        return {
            'delay_min': 1,
            'delay_max': 3,
            'stay_time': 5,
            'referers': ['https://google.com', 'https://bing.com']
        }
    
    def youtube_config(self):
        return {
            'delay_min': 2,
            'delay_max': 5,
            'stay_time': 10,
            'referers': ['https://www.google.com/', 'https://m.youtube.com/']
        }
    
    def tiktok_config(self):
        return {
            'delay_min': 1,
            'delay_max': 3,
            'stay_time': 8,
            'referers': ['https://www.tiktok.com/', 'https://vm.tiktok.com/']
        }
    
    def instagram_config(self):
        return {
            'delay_min': 2,
            'delay_max': 4,
            'stay_time': 7,
            'referers': ['https://www.instagram.com/', 'https://www.google.com/']
        }
    
    def facebook_config(self):
        return {
            'delay_min': 3,
            'delay_max': 6,
            'stay_time': 12,
            'referers': ['https://www.facebook.com/', 'https://l.facebook.com/']
        }
    
    def get_website_headers(self):
        """Headers khusus website"""
        config = self.get_config()
        referer = random.choice(config['referers'])
        
        return {
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'Referer': referer,
        }
    
    def simulate_view(self):
        """Simulasi view realistis untuk website"""
        config = self.get_config()
        
        try:
            headers = self.get_website_headers()
            
            # Request utama
            response = self.session.get(
                self.target_url,
                headers=headers,
                timeout=15,
                allow_redirects=True
            )
            
            if response.status_code in [200, 301, 302]:
                self.successful_views += 1
                stay_time = random.randint(config['stay_time']//2, config['stay_time'])
                
                print(f"✅ [{self.successful_views}] {self.domain} - Stay: {stay_time}s - Status: {response.status_code}")
                
                # Simulate stay time (human-like)
                time.sleep(stay_time)
                
                # Optional: scroll simulation (headless browser needed for real scroll)
                return True
            else:
                print(f"❌ [{response.status_code}] {self.domain}")
                return False
                
        except Exception as e:
            print(f"❌ Error {self.domain}: {str(e)[:50]}")
            return False
    
    def run(self, threads=1):
        """Jalankan auto views"""
        print(f"🌐 Target: {self.target_url}")
        print(f"📊 Total Views: {self.views_count:,}")
        print(f"🔧 Config: {self.domain} | Threads: {threads}")
        print("-" * 60)
        
        if threads > 1:
            self.run_multithread(threads)
        else:
            self.run_single_thread()
    
    def run_single_thread(self):
        """Single thread"""
        for i in range(self.views_count):
            self.simulate_view()
            config = self.get_config()
            delay = random.uniform(config['delay_min'], config['delay_max'])
            time.sleep(delay)
        
        print(f"\n🎉 SELESAI! Total: {self.successful_views:,}/{self.views_count:,}")
    
    def run_multithread(self, threads):
        """Multi thread"""
        import concurrent.futures
        
        views_per_thread = self.views_count // threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for t in range(threads):
                for _ in range(views_per_thread):
                    future = executor.submit(self.simulate_view)
                    futures.append(future)
                    time.sleep(0.1)
        
        print(f"\n🎉 SELESAI! Total: {self.successful_views:,}/{self.views_count:,}")

# 🚀 USAGE
if __name__ == "__main__":
    print("🔥 WEBSITE AUTO VIEWS BOT")
    print("1. YouTube  2. TikTok  3. Instagram  4. Facebook  5. Custom")
    
    url = input("\n📎 Masukkan URL Website: ").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    views = int(input("📊 Jumlah Views: ") or 1000)
    threads = int(input("🔄 Jumlah Threads (1-20): ") or 1)
    
    bot = WebsiteAutoViews(url, views)
    bot.run(threads)
