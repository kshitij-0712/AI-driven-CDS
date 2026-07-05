import os
import json
import logging
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
import httpx

logger = logging.getLogger(__name__)

class AppStructureParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.title = ""
        self.in_title = False
        self.links = []
        self.forms = []
        self.current_form = None
        self.styles = []
        self.in_style = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "title":
            self.in_title = True
        elif tag == "style":
            self.in_style = True
        elif tag == "a":
            href = attrs_dict.get("href")
            if href:
                self.links.append(href)
        elif tag == "form":
            action = attrs_dict.get("action", "")
            method = attrs_dict.get("method", "GET").upper()
            self.current_form = {
                "action": action,
                "method": method,
                "inputs": []
            }
        elif tag == "input" and self.current_form is not None:
            input_type = attrs_dict.get("type", "text")
            name = attrs_dict.get("name")
            placeholder = attrs_dict.get("placeholder", "")
            if name:
                self.current_form["inputs"].append({
                    "name": name,
                    "type": input_type,
                    "placeholder": placeholder
                })
        elif tag == "button" and self.current_form is not None:
            btn_type = attrs_dict.get("type", "submit")
            if btn_type == "submit":
                name = attrs_dict.get("name")
                if name:
                    self.current_form["inputs"].append({
                        "name": name,
                        "type": "submit",
                        "placeholder": ""
                    })

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag == "style":
            self.in_style = False
        elif tag == "form":
            if self.current_form:
                self.forms.append(self.current_form)
                self.current_form = None

    def handle_data(self, data):
        if self.in_title:
            self.title = data.strip()
        elif self.in_style:
            self.styles.append(data.strip())

class AppCrawler:
    def __init__(self, target_url, output_path):
        self.target_url = target_url.rstrip("/")
        self.output_path = output_path
        self.visited = set()
        self.structure = {
            "target_url": self.target_url,
            "theme": "",
            "pages": {}
        }

    async def crawl(self):
        to_visit = { self.target_url + "/" }
        
        async with httpx.AsyncClient() as client:
            while to_visit:
                curr_url = to_visit.pop()
                if curr_url in self.visited:
                    continue
                
                logger.info(f"Crawling: {curr_url}")
                self.visited.add(curr_url)
                
                try:
                    response = await client.get(curr_url, timeout=5)
                    if response.status_code != 200:
                        continue
                    
                    content_type = response.headers.get("content-type", "")
                    if "text/html" not in content_type:
                        continue
                        
                    html_content = response.text
                    parser = AppStructureParser(self.target_url)
                    parser.feed(html_content)
                    
                    parsed_url = urlparse(curr_url)
                    path = parsed_url.path if parsed_url.path else "/"
                    
                    self.structure["pages"][path] = {
                        "title": parser.title,
                        "links": list(set(parser.links)),
                        "forms": parser.forms
                    }
                    
                    if not self.structure["theme"] and parser.styles:
                        combined_styles = "\n".join(parser.styles)
                        root_match = re.search(r":root\s*\{([^}]+)\}", combined_styles)
                        if root_match:
                            self.structure["theme"] = root_match.group(0)
                        else:
                            self.structure["theme"] = combined_styles[:1000]

                    for link in parser.links:
                        full_link = urljoin(curr_url, link)
                        parsed_link = urlparse(full_link)
                        parsed_target = urlparse(self.target_url)
                        
                        if parsed_link.netloc == parsed_target.netloc:
                            clean_link = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                            if clean_link not in self.visited:
                                to_visit.add(clean_link)
                                
                except Exception as e:
                    logger.error(f"Error crawling {curr_url}: {e}")
                    
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(self.structure, f, indent=2)
        logger.info(f"App structure saved to {self.output_path}")

if __name__ == "__main__":
    import asyncio
    import argparse
    
    logging.basicConfig(level=logging.INFO)
    
    parser = argparse.ArgumentParser(description="App Crawler")
    parser.add_argument("--url", default="http://127.0.0.1:8090", help="URL to crawl")
    parser.add_argument("--out", default="./runtime/app_structure.json", help="Output path")
    args = parser.parse_args()
    
    crawler = AppCrawler(args.url, args.out)
    asyncio.run(crawler.crawl())
