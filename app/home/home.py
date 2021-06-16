# !/usr/bin/env python
# Name:     home.py
# By:       LA-Shill
# Date:     23.04.2021
# Version   1.6
# -----------------------------------------------

# Import offical and custom libraries/functions
import redis
import os
import json
import re
import time
from flask import Blueprint, render_template, request, make_response, redirect, jsonify, send_from_directory
from flask import current_app as app
from flask import Blueprint, redirect, render_template, flash, request, session, url_for
from datetime import datetime, timedelta
from rq.job import Job, get_current_job
from worker import conn
from rq import Queue, Worker
from rq.registry import StartedJobRegistry, ScheduledJobRegistry
from bson import json_util
from urllib.parse import unquote
from collections import Counter
from .. import mainDB, vulDB
from ..forms import ScanForm, SettingsForm, aRescanForm, riskRescanForm, newProjectForm, projectSettingsForm, projectSettingsDel
from ..core.dataHandler import iws_grabber, pdns_grabber, generate_node_network, vul_scan, location_verification, asset_scan, flag_check, port_flag_check, create_project, save_project_stats, rddos_prediction
from ..core.standardValues import StandardValues
from ..core.misc import tld_count, subdomain_count, overview_total_stats, per_change, latest_records, csv_export
from ..tables.models import TableBuilder

# Redis & queue setup
redis_url = os.getenv('REDISTOGO_URL')
r = redis.from_url(redis_url)
q = Queue(default_timeout=86400, connection=r)
response = r.client_list()

# Blueprint Configuration
home_bp = Blueprint(
    'home_bp', __name__,
    template_folder='templates',
    static_folder='static'
)

@home_bp.route('/export/<path:project_name>/<path:id>/<path:time_range>', methods=['GET', 'POST'])
def export(project_name, id, time_range):

    project_name = str(unquote(project_name))
    
    # Convert timeline data for MongoDB
    timeline = time_range.split(',')
    time_min = datetime.strptime(timeline[0], '%d/%m/%Y')
    time_max = datetime.strptime(timeline[1], '%d/%m/%Y')

    tmp = os.path.join(app.root_path, app.config['TMP_FOLDER'])

    if (id == "graph"):
        return send_from_directory(directory=tmp, filename="graph_latest.html")


    if (id == "iws_risks"):
        # Get latest record
        data = list(mainDB.db[project_name].find({"$and": [{"source": 'merged'}, {'timestamp':{'$gte':time_min, '$lte':time_max + timedelta(hours=24)}}]}))

        tmpData = []
        assets = []
        filteredAssets = []
        newData = []

        for record in data:
            if 'risks' in record:
                for risk in record['risks']:
                    if 'ports' in risk:
                        tmpData.append(record)
                    elif 'cve' in risk:
                        tmpData.append(record)
                    elif 'rddos' in risk:
                        tmpData.append(record)
            if 'cveData' in record:
                tmpData.append(record)
        
        # Remove duplicate based on timestamp being closes to maxtime
        for entry in tmpData:
            assets.append(entry['ip'])

        filteredAssets = list(set(assets))
        
        for ip in filteredAssets:
            tempRecords = []
            for entry in tmpData:
                if entry['ip'] == ip:
                    tempRecords.append(entry)
            
            newData.append(min(tempRecords, key=lambda x:abs(x['timestamp'] - (time_max +  timedelta(hours=24)))))
        
        data = newData

    if (id == "pdns_risks"):
        data = list(mainDB.db[project_name].find({"$and": [{"flagged": True},{"type": 'pdns'}, {'timestamp':{'$gte':time_min, '$lte':time_max + timedelta(hours=24)}}]}))
        domains = []
        newData = []

        # Remove duplicate based on timestamp being closes to maxtime
        for entry in data:
            domains.append(entry['domain'])

        n_domains = list(set(domains))
        
        for domain in n_domains:
            tempRecords = []
            for entry in data:
                if entry['domain'] == domain:
                    tempRecords.append(entry)
            
            newData.append(min(tempRecords, key=lambda x:abs(x['timestamp'] - time_max + timedelta(hours=24))))
        data = newData

    if (id == "iws_all"):
        data = list(mainDB.db[project_name].find({"$and": [{'source': {'$exists': True}},  {'type': {'$exists': False}}, {'timestamp':{'$gte':time_min, '$lte':time_max + timedelta(hours=24)}}]}))

    if (id == "pdns_all"):
        data = list(mainDB.db[project_name].find({"$and": [{"type": 'pdns'}, {'timestamp':{'$gte':time_min, '$lte':time_max + timedelta(hours=24)}}]}))

    # Generate CSV
    csv_data = csv_export(data)

    # Pass file to client
    response = make_response(csv_data)
    response.headers['Content-Type'] = 'application/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=export.csv'
    return response
    #return redirect(url_for('home_bp.overview', project_name=project_name))


@home_bp.route('/', methods=['GET', 'POST'])
def home():
    """Homepage."""
    # Time to base all stats on latest scan data
    time_now = datetime.now()
    # Variables
    totalAssets : int = 0
    risks : int = 0
    iws_risk : int = 0
    secureAssets : int = 0
    defaultVuls : int = 0
    scans = {'name' : '', 'secureAssets' : 0, 'risks' : 0, 'totalAssets' : 0, 'defaultVuls' : 0}
    scanStats = []
    sumAssets = 0
    sumSecure = 0
    sumRisks = 0
    sumDefault = 0
    

    for collection in mainDB.db.list_collection_names():
        if collection != 'settings' :
            # OLD - Set for old data format, backup
            scans['name'] = collection

            project_data = list(mainDB.db[collection].find({'project_name' : collection}))

            # Total Asset Count
            data = list(mainDB.db[collection].find({"source": 'merged'}))
            assets_timebased = []
            assets_timebased = latest_records(data, project_data[0])


        
            totalAssets += len(assets_timebased)
            # Total Assets - Individual Scan
            scans['totalAssets'] = len(assets_timebased)

            # Total Risk Count (IWS)
            riskyAssets = []
            for record in assets_timebased:
                if 'risks' in record:
                    for risk in record['risks']:
                        if 'ports' in risk:
                            riskyAssets.append(record['ip'])
                        elif 'cve' in risk:
                            riskyAssets.append(record['ip'])
                        elif 'rddos' in risk:
                            riskyAssets.append(record['ip'])
                if 'cveData' in record:
                    riskyAssets.append(record['ip'])

            risks += len(list(set(riskyAssets)))

            # Secure Asset Count (IWS)
            secureAssets += (len(assets_timebased) - len(list(set(riskyAssets))))
            # Secure Asset - Individual Scan
            scans['secureAssets'] = (len(assets_timebased) - len(list(set(riskyAssets))))

            # Total Risk Count (PDNS)
            data = list(mainDB.db[collection].find({"$and": [{"flagged":  True}, {'type': 'pdns'}]}))
            done = set()
            pdns = []
            pdns_timebased = []
            for record in data:
                if record['domain'] not in done:
                    done.add(record['domain'])
                    pdns.append(record)
            for asset in pdns:
                tempRecords = []
                for record in data:
                    if record['domain'] == asset['domain']:
                        tempRecords.append(record)
                pdns_timebased.append(min(tempRecords, key=lambda x:abs(x.get('timestamp', time_now) - time_now)))
            risks += len(pdns_timebased)        
            # Risky Assets - Individual Scan
            scans['risks'] = (len(list(set(riskyAssets))) + len(pdns_timebased))

            # Default Vuls Needs finished
            default = []
            for entry in assets_timebased:
                if 'risks' in entry:
                    for risk in entry['risks']:
                        if 'default' in risk:
                            default.append(entry['ip'])
                            break
            
            defaultVuls += len(list(set(default)))
            # Default Vul - Individual Scan
            scans['defaultVuls'] = len(list(set(default)))

            # Append Individual Scan List
            scanStats.append(scans.copy())

            # Stats from last 24 hour period - figures need to be less than but as close as possible to this figure (put above into function and just pass in time param and return desired) - NVM, do it accumulatively

            try:
                data = list(mainDB.db[collection].find({"project_name": collection}))
                # Meta - Individual Scan
                scans['name'] = data[0]['project_name']
                sumAssets += data[0]['last_stats']['totalAssets']
                sumSecure += data[0]['last_stats']['secureAssets']
                sumRisks += data[0]['last_stats']['risks']
                sumDefault += data[0]['last_stats']['defaultConfig']
            except:
                print('[INFORMANT] Detected a invalid collection format. Have you recently modified the project settings?')

    stats = {'totalScans' : (len(mainDB.db.list_collection_names()) -1 ), 'secureAssets' : secureAssets, 'risks' : risks, 'totalAssets' : totalAssets, 'defaultVuls' : defaultVuls}
    change_stats = {}
    change_stats['totalAssets_change'] = per_change(totalAssets, sumAssets)
    change_stats['secureAssets_change'] = per_change(secureAssets, sumSecure)
    change_stats['riskyAssets_change'] = per_change(risks, sumRisks)
    change_stats['defaultAssets_change'] = per_change(defaultVuls, sumDefault)


    """ New Project """
    new_project = newProjectForm()
    """ Scan """
    form = ScanForm()
    if request.method == 'POST':
        if form.is_submitted():
            scan_range = form.scan_range.data
            max_records = form.max_records.data
            if 'Shodan' in form.options.data:
                shodan = True
            else:
                shodan = False

            if 'Censys' in form.options.data:
                censys = True
            else:
                censys = False

            if 'BinaryEdge' in form.options.data:
                binaryedge = True
            else:
                binaryedge = False

            if 'Onyphe' in form.options.data:
                onyphe = True
            else:
                onyphe = False

            if 'ThreatCrowd' in form.options.data:
                threatcrowd = True
            else:
                threatcrowd = False

            if 'ThreatMiner' in form.options.data:
                threatminer = True
            else:
                threatminer = False

            if 'Robtex' in form.options.data:
                robtex = True
            else:
                robtex = False

            if 'Daloo' in form.options.data:
                daloo = True
            else:
                daloo = False

            if 'FarSight' in form.options.data:
                farsight = True
            else:
                farsight = False

            if 'DNSGrep' in form.options.data:
                dnsgrep = True
            else:
                dnsgrep = False

            if (onyphe == True and shodan == False and binaryedge == False and censys == False):
                flash('Onyphe cannot be run on it\'s own! Scan aborted.', 'warning')
                return redirect(url_for('home_bp.home'))
            if (dnsgrep == True and farsight == False and daloo == False and robtex == False and threatcrowd == False and threatminer == False):
                flash('DNSGrep cannot be run on it\'s own! Scan aborted.', 'warning')
                return redirect(url_for('home_bp.home'))
            # Run scan
            title = scan_range + '_asset_scan'
            scan_name = re.sub(r'[/]', "_", scan_range)
            create_project(scan_name, scan_range, max_records)
            task = q.enqueue(asset_scan, scan_range, shodan, censys, binaryedge, onyphe, max_records, threatcrowd, threatminer, robtex, daloo, farsight, dnsgrep, False, scan_name, job_id=title)
            flash('Asset Discovery scan started. Creating project: ' + str(scan_range), 'success')
            return redirect(url_for('home_bp.home'))
            
    return render_template('index.html', title="Dashboard", description="INFORMANT - Clean interactive dashboard.", stats=stats, jobs=q.jobs, scans=scanStats, form=form, new_project=new_project, change_stats=change_stats)


@home_bp.route('/create', methods=['POST'])
def new_project():
    new_project = newProjectForm()

    if request.method == 'POST':
        if new_project.validate_on_submit():
            create_project(new_project.project_name.data, new_project.scan_range.data, new_project.max_records.data)
            
            flash('Project successfully created!', 'success')
            return redirect(url_for('home_bp.home'))
        flash('Failed to created project, check your entering valid data.', 'danger')

    return redirect(url_for('home_bp.home'))


@home_bp.route('/settings', methods=['GET', 'POST'])
def settings():
    # Create form
    form = SettingsForm()

    # Get current setting values
    settings = mainDB.db['settings'].find({})
    settings_data = {'CENSYS_API_ID' : settings[0]['CENSYS_API_ID'], 'CENSYS_API_SECRET' : settings[0]['CENSYS_API_SECRET'], 'SHODAN_API_KEY' : settings[0]['SHODAN_API_KEY'], 'BINARY_EDGE_API_KEY' : settings[0]['BINARY_EDGE_API_KEY'], 'ONYPHE_API_KEY' : settings[0]['ONYPHE_API_KEY'], 'FARSIGHT_API_KEY' : settings[0]['FARSIGHT_API_KEY'], 'HIGH_RISK_PORTS' : settings[0]['HIGH_RISK_PORTS'], 'GEO_LOCATION' : settings[0]['GEO_LOCATION']}

    # Check for successful form submission
    if request.method == 'POST':
        if form.validate_on_submit:
            mainDB.db['settings'].update({"_id":settings[0]['_id']},{"$set":{"SHODAN_API_KEY":str(form.shodanApiKey.data)}})
            mainDB.db['settings'].update({"_id":settings[0]['_id']},{"$set":{"CENSYS_API_ID":str(form.censysUID.data)}})
            mainDB.db['settings'].update({"_id":settings[0]['_id']},{"$set":{"CENSYS_API_SECRET":str(form.censysApiKey.data)}})
            mainDB.db['settings'].update({"_id":settings[0]['_id']},{"$set":{"BINARY_EDGE_API_KEY":str(form.beApiKey.data)}})
            mainDB.db['settings'].update({"_id":settings[0]['_id']},{"$set":{"ONYPHE_API_KEY":str(form.onypheApiKey.data)}})
            mainDB.db['settings'].update({"_id":settings[0]['_id']},{"$set":{"FARSIGHT_API_KEY":str(form.farsightApiKey.data)}})
            mainDB.db['settings'].update({"_id":settings[0]['_id']},{"$set":{"GEO_LOCATION":str(form.geoLocation.data)}})
            ports_str = form.highRiskPorts.data.split (",")
            ports = []
            try:
                for port in ports_str:
                    ports.append(int(port))
            except Exception as e:
                pass

            if (settings[0]['HIGH_RISK_PORTS'] == ports):
                print("No need to update ports")
            else:
                mainDB.db['settings'].update({"_id":settings[0]['_id']},{"$set":{"HIGH_RISK_PORTS":ports}})
                #for collection in mainDB.db.list_collection_names():
                    #if collection != "settings":
                        #port_flag_check(collection)

            flash('Successfully Updated Settings.', 'success')
            return redirect(url_for('home_bp.settings'))

    return render_template('settings.html',  title="Settings", description="INFORMANT - IWS and PDNS configuration page.", form=form, standard=settings_data)


@home_bp.route('/<path:project_name>/settings/del', methods=['POST'])
def project_del(project_name):
    project_del= projectSettingsDel()
    if request.method == 'POST':
        if project_del.validate_on_submit():
            if (project_del.project_name.data == project_name):
                try:
                    # Wipe job queue
                    for job in q.jobs:
                        if project_name in job.id:
                            job.cancel()

                    # Delete data
                    mainDB.db.drop_collection(project_name)
                except Exception as e:
                    print("Error on project deletion: " + str(e))
                flash('Project deleted', 'success')
                return redirect(url_for('home_bp.home'))
            else:
                flash('Project deletion attempt failed', 'warning')
                return redirect(url_for('home_bp.overview', project_name=project_name))


@home_bp.route('/<path:project_name>/settings', methods=['POST'])
def project_settings(project_name):
    # Forms
    project_name = str(unquote(project_name))
    project_settings = projectSettingsForm()
    if request.method == 'POST':
        if project_settings.validate_on_submit():
            projects = list(mainDB.db.list_collection_names())
            if project_settings.project_name.data in projects:
                if project_settings.project_name.data == project_name:
                    pass
                else:
                    flash('That project name already exists.', 'danger')
                    return redirect(url_for('home_bp.overview', project_name=project_name))
                    
            workers = Worker.all(connection=r)
            workers = Worker.all(queue=q)
            if project_settings.project_name.data != project_name:
                for job in q.jobs:
                    
                    cur_job = Job.fetch(job.id, connection=r)
                    if project_name in job.id:
                        flash('You can\'t change the project name whilst scans are in progress/queued.', 'danger')
                        return redirect(url_for('home_bp.overview', project_name=project_name))
                    
                if(len(workers) > 0):
                    try:
                        for worker in workers:
                            if worker.state == 'busy':
                                flash('You can\'t change the project name whilst scans are in progress/queued.', 'danger')
                                return redirect(url_for('home_bp.overview', project_name=project_name))
                    except Exception:
                        pass

            mainDB.db[project_name].update({'project_name' : project_name},{"$set":{"last_scan_range":str(project_settings.scan_range.data)}})
            mainDB.db[project_name].update({'project_name' : project_name},{"$set":{"max_records":int(project_settings.max_records.data)}})
            if project_settings.project_name.data != project_name:
                mainDB.db[project_name].update({'project_name' : project_name},{"$set":{"project_name":str(project_settings.project_name.data)}})
                mainDB.db[project_name].rename(str(project_settings.project_name.data))
            flash('Project settings successfully updated.', 'success')
        else:
            flash('Invalid project settings, not updated.', 'danger')

    return redirect(url_for('home_bp.overview', project_name=project_settings.project_name.data))


@home_bp.route('/overview/<path:project_name>', methods=['GET'])
def overview(project_name):
    project_name = str(unquote(project_name))
    """Overview"""
    project_data = mainDB.db[project_name].find({'project_name' : project_name})

    for r in project_data:
       project = r

    risks = len(list(mainDB.db[project_name].find({'$or': [{'cveData': {'$exists': True}}, {'risks': {'$exists': True}}]})))
    risks += mainDB.db[project_name].count_documents({"flagged":  True})
    defaultVuls = 0

    # Forms
    a_rescan_form = aRescanForm()
    risk_rescan_form = riskRescanForm()
    project_settings = projectSettingsForm()
    project_del= projectSettingsDel()

    return render_template('overview.html', title="Overview", description="Overview of discovered assets.",scan_name=project_name, a_rescan_form=a_rescan_form, risk_rescan_form=risk_rescan_form, project_del=project_del, max_records=project['max_records'], scan_r=project['last_scan_range'], last_run=project['last_run'], first_run=project['created_at'], project_settings=project_settings)


@home_bp.route('/overview/<path:project_name>/<path:time_range>/stats', methods=['GET'])
def overview_stats(project_name, time_range):
    project_name = str(unquote(project_name))
    
    # Convert timeline data for MongoDB
    timeline = time_range.split(',')
    time_min = datetime.strptime(timeline[0], '%d/%m/%Y')
    time_max = datetime.strptime(timeline[1], '%d/%m/%Y')

    # Gather all required data
    raw_data = list(mainDB.db[project_name].find({"$and": [{'timestamp':{'$gte':time_min + timedelta(hours=24), '$lte':time_max + timedelta(hours=24)}}]}))

    # Merged assets
    merged = []
    for asset in raw_data:
        if(asset.get('source') == "merged"):
            merged.append(asset)

    # IWS Platform Stats
    merged_assets = (1 for k in raw_data if (k.get('source') == 'merged' and k.get('ip') != "None"))
    shodan_assets = (1 for k in raw_data if (k.get('source') == '_shodan' and k.get('ip') != "None"))
    censys_assets = (1 for k in raw_data if (k.get('source') == '_censys' and k.get('ip') != "None"))
    be_assets = (1 for k in raw_data if (k.get('source') == '_binaryedge' and k.get('ip') != "None"))
    onyphe_assets = (1 for k in raw_data if (k.get('source') == '_onyphe' and k.get('ip') != "None"))

    # Detailed IWS Stats
    known_vul_assets = (1 for k in raw_data if (k.get('source') == 'merged' and k.get('cveData')))
    default_vul_cves = []
    cves_total_score = []
    total_vul_services = 0
    h_risk_port_assets = 0
    obfuscated_services = 0
    h_risk_ports = 0
    cves = []
    vul_service = []
    service_total = 0
    for asset in merged:
        if(asset.get('risks')):
            for risk in asset['risks']:
                if ('obfuscated' in risk):
                    obfuscated_services += 1
                if ('ports' in risk):
                    h_risk_port_assets += 1
                    h_risk_ports += len(risk['ports'])
                if ('cve' in risk):
                    default_vul_cves.append(risk['cve']['cve'])
            
        if(asset.get('cveData')):
            total_vul_services += len(asset['cveData'])
            for service in asset['cveData']:
                service_name = service[0].get('manufacturer') + ' ' + service[0].get('product') + ' ' + service[0].get('version') 
                vul_service.append(service[0]['port'])
                for cve in service:
                    cves.append(cve['cve'])
                    cves_total_score.append(cve['cvss2'])
        
        if(asset.get('banners')):
            for banner in asset['banners']:
                service_total += 1

    
    vul_services_by_port = Counter(vul_service)
    cves_total = Counter(cves)
    default_cves_total = Counter(default_vul_cves)

    identified_ports = Counter()
    for asset in merged:
        identified_ports += Counter(asset.get('ports'))

    most_common_ports = dict(identified_ports.most_common(5))
    vul_services_by_port = dict(vul_services_by_port)
    identified_ports = dict(identified_ports)
    default_cves_total = dict(default_cves_total)
    cves_total = dict(cves_total)

    print("-- Additional Stats --")
    print("Total Services: ", str(service_total))
    print("Total Vulnerable Services: ", str(sum(vul_services_by_port.values())))
    print("Total Default CVEs: ", str(sum(default_cves_total.values())))
    print("Total CVEs: ", str(sum(cves_total.values())))
    print("Total Exposed Ports: ", str(sum(identified_ports.values())))
    for cve in cves_total_score:
        print(cve)

    # IWS Sources Comparison
    graph_01 = {'values' : [sum(shodan_assets), sum(censys_assets), sum(be_assets), sum(onyphe_assets)], 'labels' : ['Shodan', 'Censys', 'BinaryEdge', 'Onyphe']}
    # Port Comparison
    graph_02 = {'values' : list(identified_ports.values()), 'labels' : list(identified_ports.keys())}
    graph_03 = {'values' : list(most_common_ports.values()), 'labels' : list(most_common_ports.keys())}
    # CVES
    graph_04 = {'values' : list(cves_total.values()), 'labels' : list(cves_total.keys())}
    graph_05 = {'values' : list(vul_services_by_port.values()), 'labels' : list(vul_services_by_port.keys())}
    graph_06 = {'values' : list(default_cves_total.values()), 'labels' : list(default_cves_total.keys())}
    return render_template('overview_stats.html', title="Statistical Overview", description="INFORMANT - Statistical project overview.", project_name=project_name, graph_01=graph_01, graph_02=graph_02, graph_03=graph_03, graph_04=graph_04, graph_05=graph_05, graph_06=graph_06)


@home_bp.route('/discovery/<path:project_name>', methods=['POST'])
def rescan_assets(project_name):
    project_name = str(unquote(project_name))
    """Asset Rescan"""
    settings = mainDB.db['settings'].find({})

    form = aRescanForm()
    if request.method == 'POST':
        if 'Shodan' in form.options.data:
            shodan = True
        else:
            shodan = False

        if 'Censys' in form.options.data:
            censys = True
        else:
            censys = False

        if 'BinaryEdge' in form.options.data:
            binaryedge = True
        else:
            binaryedge = False

        if 'Onyphe' in form.options.data:
            onyphe = True
        else:
            onyphe = False

        if 'ThreatCrowd' in form.options.data:
            threatcrowd = True
        else:
            threatcrowd = False

        if 'ThreatMiner' in form.options.data:
            threatminer = True
        else:
            threatminer = False

        if 'Robtex' in form.options.data:
            robtex = True
        else:
            robtex = False

        if 'Daloo' in form.options.data:
            daloo = True
        else:
            daloo = False

        if 'FarSight' in form.options.data:
            farsight = True
        else:
            farsight = False

        if 'DNSGrep' in form.options.data:
            dnsgrep = True
        else:
            dnsgrep = False

        # Get required data
        project_data = mainDB.db[project_name].find({'project_name' : project_name})
        for r in project_data:
            last_scan_range = r['last_scan_range']
            max_records = r['max_records']

        # Run scan
        if 'GEO Validation (Active)' in form.options.data:
            title = scan_name + '_geo_scan'
            task = q.enqueue(location_verification, scan_name, settings[0]['GEO_LOCATION'], job_id=title)
            flash('GEO Location Verification Added To Task Queue.', 'info')
        if (shodan == True or censys == True or binaryedge == True or onyphe == True or threatcrowd == True or threatminer == True or robtex == True or daloo == True or farsight == True or dnsgrep == True):
            title = project_name + '_asset_scan'
            task = q.enqueue(asset_scan, last_scan_range, shodan, censys, binaryedge, onyphe, max_records, threatcrowd, threatminer, robtex, daloo, farsight, dnsgrep, True, project_name, job_id=title)
            flash('Asset Discovery Scan Added To Task Queue.', 'info')
    return redirect(url_for('home_bp.overview', project_name=project_name))


@home_bp.route('/assess/<path:scan_name>', methods=['POST'])
def rescan_assessment(scan_name):
    scan_name = str(unquote(scan_name))
    """Asset Rescan"""
    asn = -1
    risk_rescan_form = riskRescanForm()
    if request.method == 'POST':
        if 'Vulnerability Assessment' in risk_rescan_form.options.data:
            title = scan_name + '_vul_scan'
            task = q.enqueue(vul_scan, scan_name, job_id=title)
            flash('Vulnerability Assessment Added To Task Queue.', 'info')
        if 'DNS Risk Assessment' in risk_rescan_form.options.data:
            ipList = []
            for doc in mainDB.db[scan_name].find({}):
                if 'source' in doc:
                    if doc['source'] == 'merged':
                        ipList.append(doc['ip'])
                        if 'asn' in doc:
                            asn = str(doc['asn'])
                            if not asn.islower() and asn.isupper():
                                asn = doc['asn'][2:]
            flag_check(scan_name, asn)
            flash('DNS Risk Assessment Complete.', 'success')

    return redirect(url_for('home_bp.overview', project_name=scan_name))


@home_bp.route('/tables/<path:schema>/<path:col>/<path:time_range>', methods=['GET'])
def serverside_table_content(schema, col, time_range):
    col = str(unquote(col))
    
    # Convert timeline data for MongoDB
    timeline = time_range.split(',')
    time_min = datetime.strptime(timeline[0], '%d/%m/%Y')
    time_max = datetime.strptime(timeline[1], '%d/%m/%Y')

    project_data = mainDB.db[col].find({'project_name' : col})
    for r in project_data:
       project = r


    table_builder = TableBuilder()
    if(schema == 'PDNS_0'):
        #data = list(mainDB.db[col].find({"flagged":  True}))
        data = list(mainDB.db[col].find({"$and": [{"flagged": True},{"type": 'pdns'}, {'timestamp':{'$gte':time_min, '$lte':time_max + timedelta(hours=24)}}]}))
        domains = []
        newData = []

        # Remove duplicate based on timestamp being closes to maxtime
        for entry in data:
            domains.append(entry['domain'])

        n_domains = list(set(domains))
        
        for domain in n_domains:
            tempRecords = []
            for entry in data:
                if entry['domain'] == domain:
                    tempRecords.append(entry)
            
            newData.append(min(tempRecords, key=lambda x:abs(x['timestamp'] - time_max + timedelta(hours=24))))
        data = newData

    elif(schema == 'PDNS_1'):
        # TO IMPROVE PERFORMANCE PASS IN PAGINATION VALUES TO MONGO QUERY - Sanatise values first (skip and limit paramaters) 
        # https://www.codementor.io/@arpitbhayani/fast-and-efficient-pagination-in-mongodb-9095flbqr
        start = time.process_time()
        data = list(mainDB.db[col].find({"$and": [{"type": 'pdns'}, {'timestamp':{'$gte':time_min, '$lte':time_max + timedelta(hours=24)}}]}))
        print(time.process_time() - start)
    elif(schema == 'IWS_0'):
        # Get latest record
        data = list(mainDB.db[col].find({"$and": [{"source": 'merged'}, {'timestamp':{'$gte':time_min, '$lte':time_max + timedelta(hours=24)}}]}))

        tmpData = []
        assets = []
        filteredAssets = []
        newData = []

        for record in data:
            if 'risks' in record:
                for risk in record['risks']:
                    if 'ports' in risk:
                        tmpData.append(record)
                    elif 'cve' in risk:
                        tmpData.append(record)
                    elif 'rddos' in risk:
                        tmpData.append(record)
            if 'cveData' in record:
                tmpData.append(record)
        
        # Remove duplicate based on timestamp being closes to maxtime
        for entry in tmpData:
            assets.append(entry['ip'])

        filteredAssets = list(set(assets))
        
        for ip in filteredAssets:
            tempRecords = []
            for entry in tmpData:
                if entry['ip'] == ip:
                    tempRecords.append(entry)
            
            newData.append(min(tempRecords, key=lambda x:abs(x['timestamp'] - (time_max +  timedelta(hours=24)))))
        
        data = newData

    elif(schema == 'IWS_1'):
        data = list(mainDB.db[col].find({"$and": [{"source": 'merged'}, {'timestamp':{'$gte':time_min, '$lte':time_max + timedelta(hours=24)}}]}))

    res = table_builder.collect_data_serverside(request, data, schema)
    return jsonify(res)


@home_bp.route('/overview/<path:project_name>/iws', methods=['GET'])
def iws(project_name):
    project_name = str(unquote(project_name))
    """Overview"""
    data = mainDB.db[project_name].find({})

    project_data = mainDB.db[project_name].find({'project_name' : project_name})
    for r in project_data:
       project = r

    risks = len(list(mainDB.db[project_name].find({'$or': [{'cveData': {'$exists': True}}, {'risks': {'$exists': True}}]})))
    risks += mainDB.db[project_name].count_documents({"flagged":  True})
    defaultVuls = 0

    defaultV = mainDB.db[project_name].find({"$and": [{"source":  'merged'}, {"cveData": {'$exists': True}}]})
    for entry in defaultV:
        for service in entry['cveData']:
            for cve in service:
                if(cve['vul_by_default'] == True):
                    defaultVuls += 1
                    
    data = list(mainDB.db[project_name].find({"$and": [{"source": {'$ne': 'merged'}}, {"type": {'$exists': False}}]}))

    for d in data:
        del d['_id']
        if 'project_name' in d:
            d['created_at'] = d['created_at'].strftime('%a, %d %b %Y %H:%M:%S')
            d['last_run'] = d['last_run'].strftime('%a, %d %b %Y %H:%M:%S')
        else:
            d['timestamp'] = d['timestamp'].strftime('%a, %d %b %Y %H:%M:%S')
                
    return render_template('raw_iws_data.html', title="IWS Overview", description="IWS overview of discovered assets.", scan_name=project_name, data=json.dumps(data), last_run=project['last_run'], first_run=project['created_at'])


@home_bp.route('/overview/<path:project_name>/map/<path:time_range>', methods=['GET'])
def network_map(project_name, time_range):
    project_name = str(unquote(project_name))
    """Network Map"""

    # Convert timeline data for MongoDB
    timeline = time_range.split(',')
    time_min = datetime.strptime(timeline[0], '%d/%m/%Y')
    time_max = datetime.strptime(timeline[1], '%d/%m/%Y')

    graphScriptObject = generate_node_network(project_name, time_min, time_max)
    
    return render_template('network_map.html', scan_name=project_name, graph=graphScriptObject, title="Network Diagram", time_range=time_range)


@home_bp.route('/overview/<path:project_name>/view/<path:ip_addr>/data/<path:time_range>', methods=['POST'])
def ip_addr_data(project_name, ip_addr, time_range):
    """Overview""" 
    project_name = str(unquote(project_name))
    timeline = time_range.split(',')
    time_min = datetime.strptime(timeline[0], '%d/%m/%Y')
    time_max = datetime.strptime(timeline[1], '%d/%m/%Y')

    project_data = list(mainDB.db[project_name].find({"$and": [{'ip' : ip_addr},{'timestamp':{'$gte':time_min, '$lte':time_max + timedelta(hours=24)}}]}))

    for r in project_data:
        del r['_id']

    return jsonify(project_data)


@home_bp.route('/overview/<path:project_name>/view/<path:ip_addr>/<path:time_range>', methods=['GET'])
def ip_addr_view(project_name, ip_addr, time_range):
    project_name = str(unquote(project_name))
    project_data = list(mainDB.db[str(unquote(project_name))].find({'project_name' : str(unquote(project_name))}))
    timeline = time_range.split(',')
    time_min = datetime.strptime(timeline[0], '%d/%m/%Y')
    time_max = datetime.strptime(timeline[1], '%d/%m/%Y')
    
    return render_template('ip_addr_view.html', title="IWS Overview", description="Individual asset overview.", project_info=project_data[0], ip=ip_addr, first_run=time_min, last_run=time_max)


@home_bp.route('/stats/<path:project_name>/<path:schema>/<path:time_range>', methods=['POST'])
def stats(project_name, schema, time_range):
    project_name = str(unquote(project_name))

    # Convert times
    timeline = time_range.split(',')
    time_min = datetime.strptime(timeline[0], '%d/%m/%Y')
    time_max = datetime.strptime(timeline[1], '%d/%m/%Y')
    tldList = []
    if schema == "PDNS_1":
        start = time.process_time()
        data = mainDB.db[project_name].find({"$and": [{'timestamp':{'$gte':time_min + timedelta(hours=24), '$lte':time_max + timedelta(hours=24)}}]})
        print(time.process_time() - start)
        for doc in data:
            if doc['source'] == 'merged':
                if 'hostnames' in doc:
                    for hostname in doc['hostnames']:
                        tldList.append(hostname)
                if 'domains' in doc:
                    for domain in doc['domains']:
                        tldList.append(domain)
            if 'type' in doc:
                tldList.append(doc['domain'])

        data = {'tldData' : tld_count(tldList), 'subdomainData' : subdomain_count(tldList)}
        return jsonify(stats=data)


    if schema == "IWS_1":
        data = mainDB.db[project_name].find({"$and": [{"source": 'merged'}, {'timestamp':{'$gte':time_min, '$lte':time_max + timedelta(hours=24)}}]})
        # Total Assets
        assetsInv = []
        for asset in data:
            if asset['source'] == 'merged':
                assetsInv.append(asset['ip'])
   
        # Ditch dupes
        assetsInv2 = list(set(assetsInv))
        totalAssets = len(assetsInv2)

        totalScans = 0
        try:
            totalScans = assetsInv.count(assetsInv[0])

            for ip in assetsInv:
                if totalScans < assetsInv.count(ip):
                    totalScans = assetsInv.count(ip)
        except Exception:
            pass

        #seen = set()
        #totalScans = [[x,assetsInv.count(x)] for x in set(assetsInv)]  
        """
        for ip in assetsInv:
            if mainDB.db[project_name].count_documents(({"$and": [{"source":  'merged'}, {"ip": ip}]})) == 1:
                totalAssets += 1
        """                        
        data = {'totalScans' : totalScans, 'totalAssets' : totalAssets}
        return jsonify(stats=data)

    if schema == "IWS_0": 
        totalAssets, secureAssets, riskyAssets, defaultConfig = overview_total_stats(project_name, schema, time_range)
        totalAssets_change = 0
        secureAssets_change = 0
        riskyAssets_change = 0
        defaultAssets_change = 0
        # Percentage Change Stats - Performance issues need rectified
        """
        cur_data = list(mainDB.db[project_name].find({"$and": [{"source": 'merged'}, {'timestamp':{'$gte':time_max, '$lte':time_max + timedelta(hours=24)}}]}).sort("timestamp", -1))
        prev_data = validAssets #list(mainDB.db[project_name].find({"$and": [{"source": 'merged'}, {'timestamp':{'$gte':time_min, '$lte':time_min + timedelta(hours=24)}}]}).sort("timestamp", -1))
        tmpData = []
        assets = []
        filteredAssets = []
        cur_validAssets = []

        for record in data:
            if 'risks' in record:
                tmpData.append(record)
            if 'cveData' in record:
                tmpData.append(record)
        
        # Remove duplicate based on timestamp being closes to maxtime
        for entry in tmpData:
            assets.append(entry['ip'])

        filteredAssets = list(set(assets))
        
        for ip in filteredAssets:
            tempRecords = []
            for entry in tmpData:
                if entry['ip'] == ip:
                    tempRecords.append(entry)
            
            cur_validAssets.append(min(tempRecords, key=lambda x:abs(x['timestamp'] - time_max)))
    

        totalAssetsPrev = len(prev_data)
        totalAssetsNow = len(cur_data)

        vulAssetListPrev = []
        vulAssetListNow= []
        defaultConfig1 = 0
        riskyAssetsPrev = 0 
        riskyAssetsNow = 0
        defaultAssetsPrev = 0 
        defaultAssetsNow = 0
        
        for record in cur_validAssets:
            if 'risks' in record or 'cveData' in record:
                riskyAssetsPrev += 1
                if 'cveData' in record:
                    vulAssetListPrev.append(record)

        for record in cur_validAssets:
            if 'risks' in record or 'cveData' in record:
                riskyAssetsNow += 1
                if 'cveData' in record:
                    vulAssetListNow.append(record)


        for entry in vulAssetListPrev:
            for service in entry['cveData']:
                for cve in service:
                    if(cve['vul_by_default'] == True):
                        defaultAssetsPrev += 1

        for entry in vulAssetListNow:
            for service in entry['cveData']:
                for cve in service:
                    if(cve['vul_by_default'] == True):
                        defaultAssetsNow += 1
        

        secureAssetsPrev = totalAssetsPrev - riskyAssetsPrev
        secureAssetsNow = totalAssetsNow - riskyAssetsNow 


        # Change total values
        # Total Assets
        if totalAssetsPrev == 0 and totalAssetsNow == 0:
            totalAssets_change = 0
        elif(totalAssetsNow == 0):
            totalAssets_change = ((abs(totalAssetsNow - totalAssetsPrev) / totalAssetsPrev) * 100)*-1
        else:
            totalAssets_change = (abs(totalAssetsPrev - totalAssetsNow) / totalAssetsNow) * 100

        # Risky assets
        if riskyAssetsPrev == 0 and riskyAssetsNow == 0:
            riskyAssets_change = 0
        elif(riskyAssetsNow == 0):
            riskyAssets_change = ((abs(riskyAssetsNow - riskyAssetsPrev) / riskyAssetsPrev) * 100)*-1
        else:
            riskyAssets_change = (abs(riskyAssetsPrev - riskyAssetsNow) / riskyAssetsNow) * 100

        # Secure Assets
        if secureAssetsPrev == 0 and secureAssetsNow == 0:
            secureAssets_change = 0
        elif(secureAssetsNow == 0):
            secureAssets_change = ((abs(secureAssetsNow - secureAssetsPrev) / secureAssetsPrev) * 100)*-1
        else:
            secureAssets_change = (abs(secureAssetsPrev - secureAssetsNow) / secureAssetsNow) * 100

        # Default Config Vul
        if defaultAssetsPrev == 0 and defaultAssetsNow == 0:
            defaultAssets_change = 0
        elif(defaultAssetsNow == 0):
            defaultAssets_change = ((abs(defaultAssetsNow - defaultAssetsPrev) / defaultAssetsPrev) * 100)*-1
        else:
            defaultAssets_change = (abs(defaultAssetsPrev - defaultAssetsNow) / defaultAssetsNow) * 100
        
        print(totalAssetsPrev)
        print(totalAssetsNow)
        print(totalAssets_change)
        """
        
        data = {'totalAssets' : totalAssets, 'secureAssets' : secureAssets, 'riskyAssets' : riskyAssets, 'defaultConfig' : defaultConfig, 'totalAssets_change' : totalAssets_change, 'secureAssets_change' : secureAssets_change, 'riskyAssets_change' : riskyAssets_change, 'defaultAssets_change' : defaultAssets_change}
        return jsonify(stats=data)


@home_bp.route('/overview/<path:project_name>/pdns', methods=['GET'])
def pdns(project_name):
    project_name = str(unquote(project_name))
    """Overview"""
    project_data = mainDB.db[project_name].find({'project_name' : project_name})
    for r in project_data:
       project = r

    tldList = []

    return render_template('raw_pdns_data.html', title="PDNS Overview", description="PDNS overview of discovered assets.",scan_name=project_name, last_run=project['last_run'], first_run=project['created_at'], stats=[])


@app.route('/clearscans/<path:scan_name>', methods=['POST'])
def delQue(scan_name):
    scan_name = str(unquote(scan_name))
    for job in q.jobs:
        if scan_name in job.id:
            job.cancel()

    return redirect(url_for('home_bp.overview', project_name=scan_name))


# Emergency function, not documented
@app.route('/kill', methods=['GET'])
def kill():
    q.empty()
    flash('Aborted all scans!!', 'danger')
    return redirect(url_for('home_bp.home'))


@home_bp.route('/taskqueue', methods=['POST'])
def taskqueue():

    list1 = []
    scan_running = False
    format_list = {}
    for job in q.jobs:
        cur_job = Job.fetch(job.id, connection=r)
        if len(job.args) == 1:
            format_list['type'] = 'Vulnerability Scan'
            format_list['icon'] = 'bug'
            format_list['state'] = cur_job.get_status()
        else:
            format_list['type'] = 'Asset Discovery Scan'
            format_list['icon'] = 'redo'
            format_list['state'] = cur_job.get_status()

        format_list['host'] = job.args[0]
        format_list['id'] = job.id
        format_list['created_at'] = cur_job.enqueued_at

        list1.append(format_list.copy())
    
    workers = Worker.all(connection=r)
    workers = Worker.all(queue=q)
    if(len(workers) > 0):
        try:
            for worker in workers:
                if worker.state == 'busy':
                    scan_running = True
        except Exception:
            pass

    return jsonify(jobs=list1, scan_running=scan_running)


"""Error Handling Routes"""
@app.errorhandler(404)
def not_found(e):
    """Page not found"""
    return render_template("errors/404.html", title="404", description="INFORMANT - Page not found."), 404


@app.errorhandler(400)
def bad_request(e):
    """Bad request"""
    return render_template("errors/400.html", nav=navItems, subnav=subNavItems, title="400", description="INFORMANT - Bad request, please don\'t attempt that again."), 400


@app.errorhandler(500)
def server_error(e):
    """Internal server error"""
    return render_template("errors/500.html", nav=navItems, subnav=subNavItems, title="500", description="INFORMANT - Internal server error occured. We are on the case."), 500


"""Favicon Handler"""
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')