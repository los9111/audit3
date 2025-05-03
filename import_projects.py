import csv
from datetime import datetime
from main import app, db
from models import Project

CSV_PATH = '/workspaces/codespaces-blank/data/projects.csv'

def import_projects():
    with app.app_context():
        # Make sure the table exists
        db.create_all()

        # First, print out the CSV headers so we can verify them
        with open(CSV_PATH, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            print("Found CSV columns:", reader.fieldnames)
            # Comment out the next line once headers are confirmed
           # return

        # Now actually import once you're happy the headers match
        with open(CSV_PATH, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                p = Project(
                    project_name             = row['project_name'],
                    project_type             = row['project_type'],
                    hospital                  = row['trust'],
                    specialty                 = row['speciality'],
                    year                      = int(row['year']),
                    guidelines                = row.get('guidelines', ''),
                    background                = row['background'],
                    aims                      = row['aims'],
                    objectives                = row['objectives'],
                    keywords                  = row['keywords'],
                    submitter_email_hash      = row.get('submitter_email_hash', ''),
                    date_added                = datetime.utcnow(),
                    data_protection_compliant = (row['data_protection_compliant'] == 'True'),
                    data_classification       = row['data_classification'],
                    slug                      = row['slug']
                )
                db.session.add(p)
            db.session.commit()
        print("Import complete.")

if __name__ == '__main__':
    import_projects()
