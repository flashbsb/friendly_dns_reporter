import json
import csv
from jinja2 import Environment, FileSystemLoader
import os

class Reporter:
    def __init__(self, output_dir="logs"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def export_json(self, data, filename):
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return path

    def export_csv(self, data, filename, fieldnames):
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=';')
            writer.writeheader()
            writer.writerows(data)
        return path

    def generate_html(self, context, filename, template_name="dashboard.html"):
        path = os.path.join(self.output_dir, filename)
        
        # Setup Jinja2 environment to load from core/templates
        base_dir = os.path.dirname(os.path.dirname(__file__))
        template_dir = os.path.join(base_dir, 'core', 'templates')
        
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template(template_name)
        
        html_content = template.render(context)
            
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return path
