from flask import request, render_template
from vr.threat_modeling import threat_modeling
from vr.threat_modeling.main import ThreatModeler



NAV_CAT= { "name": "Admin", "url": "admin.admin_dashboard"}

@threat_modeling.route('/threat_modeler', methods=['GET', 'POST'])
def threat_modeler():
    if request.method == 'POST':
        form = request.form
        http = request.form.get('keyname')
        ThreatModeler().read_in_responses(form)
        return "hello"
    else:
        questions = ThreatModeler().read_questions_csv()
        application_questions = {
            "workflow_one": {
                "Test Question":[
                    "Answer 1",
                    "Answer 2",
                ]
            }
        }
        return render_template('threat_modeling/threat_modeler.html', questions=questions, application_questions=application_questions)


