"""Additional trial cases; the original 19/8 assertions stay unchanged."""
import time
import json
import urllib.request
import urllib.error
import re
import socket

def setup(h):
    template=h.request('/api/v1/admin/applications/'+str(h.state['app']['id'])+'/templates',{'name':'容器功能模板','features':{'export':True,'quota':42},'default_max_activations':20,'default_days':90,'default_maintenance_days':90})
    h.request('/api/v1/admin/applications/'+str(h.state['app']['id'])+'/trial',{'trial_enabled':True,'trial_days':14,'trial_template_id':template['id']},'PATCH')
    image=h.PREFIX+'trial-expire';h.build('scripts/fixtures/trial-expire.Dockerfile',image)
    return image

def issued(h):
    out=h.request('/api/v1/admin/licenses?app_id='+str(h.state['app']['id'])+'&source=self_trial&page_size=100')['items']
    for row in out:h.SENSITIVE.add(row['key'])
    assert len(out)==1,'重启或重建新建了试用授权'
    return out[0]

def expire(h,image,license):
    name=h.PREFIX+'expire-fixture';h.containers.append(name)
    h.docker('run','--rm','--name',name,'--memory=64m','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true','-v',h.state['data_volume']+':/data',image,str(license['id']))

def cli(h):
    image=setup(h);vol=h.volume_new('trial');empty={'key':''};state={}
    def initial():
        p=h.port();state['name']=h.start('trial-initial',empty,vol,listen='127.0.0.1:'+str(p));h.ready(state['name'])
        check_interval=float(h.state['app']['next_check_in'])
        started=next_request=time.monotonic()
        deadline=started+3*check_interval
        requests=0
        while time.monotonic()<deadline:
            try:
                with urllib.request.urlopen('http://127.0.0.1:'+str(p)+'/',timeout=5) as response:
                    assert json.load(response)['features']=={'export':True,'quota':42},'模板功能项未进入程序SDK结果'
            except urllib.error.HTTPError as error:
                raw=error.read().decode('utf8','replace');reason=raw if re.fullmatch(r'[A-Z_]+',raw) else '请求被拒绝'
                raise AssertionError('程序HTTP '+str(error.code)+': '+reason) from None
            requests+=1
            next_request+=.05
            time.sleep(max(0,next_request-time.monotonic()))
        assert requests>=3,'连续请求未覆盖校验周期'
        print('TRIAL_REFRESH '+h.LANGUAGE+' requests='+str(requests)+' periods=3 interval=0.05 elapsed='+format(time.monotonic()-started,'.3f')+' PASS',flush=True)
        assert '当前为试用' in h.logs(state['name'])
        state['license']=issued(h)
        assert state['license']['features']=={'export':True,'quota':42} and state['license']['max_activations']==1
        assert len([r for r in h.activations(state['license']) if r['kind']=='floating' and r['status']=='active'])==1
    h.case(20,'只有配置试用、模板功能项、50ms连续请求跨3周期',initial)
    def restart():
        h.stop(state['name']);state['name']=h.start('trial-restart',empty,vol);h.ready(state['name']);assert issued(h)['id']==state['license']['id']
    h.case(21,'试用重启不新建授权',restart)
    def rebuild():
        h.stop(state['name']);name=h.start('trial-without-volume',empty);h.ready(name)
        assert issued(h)['id']==state['license']['id'];h.stop(name)
        state['name']=h.start('trial-return-volume',empty,vol);h.ready(state['name'])
    h.case(22,'不挂卷重建仍复用同一网络试用',rebuild)
    def outage():
        h.stop_api();h.ended(state['name'],text='SDK_GRACE_EXPIRED');h.restore_api()
        state['name']=h.start('trial-after-outage',empty,vol);h.ready(state['name'])
    h.case(23,'试用断网无宽限并退出77',outage)
    def expired():
        expire(h,image,state['license']);h.ended(state['name'],text='LICENSE_EXPIRED')
    h.case(24,'试用到期退出77',expired)
    def formal():
        formal=h.license_new(1);state['name']=h.start('trial-to-formal',formal,vol);h.ready(state['name'])
        old=issued(h);assert old['converted_at'] and old['status']=='revoked'
        assert not [r for r in h.activations(old) if r['status']=='active' and r['kind']=='floating']
        assert [r for r in h.activations(formal) if r['status']=='active' and r['kind']=='floating']
        h.stop(state['name'])
    h.case(25,'设置正式授权码转正并释放试用席位',formal)
    def disabled():
        h.request('/api/v1/admin/applications/'+str(h.state['app']['id'])+'/trial',{'trial_enabled':False,'trial_days':14},'PATCH')
        name=h.start('trial-disabled',empty,h.volume_new('trial-disabled'));h.ended(name,text='TRIAL_DISABLED')
    h.case(26,'关闭试用后新实例拒绝',disabled)

# FPM keeps its process alive and returns 503 instead of CLI exit 77.
def fpm(h,start,good,bad):
    image=setup(h);h.patch_app(next_check_in=1);empty={'key':''};state={}
    def initial():
        state['target']=start('trial-initial',empty);data=good(state['target']);assert data['is_trial']
        assert data['features']=={'export':True,'quota':42},'FPM程序未读取到试用模板功能项'
        state['license']=issued(h)
    h.case(9,'FPM只有配置可申领试用、程序可读模板功能项',initial)
    def restart():
        h.docker('restart','-t','8',state['target']['fpm'])
        def fpm_listening():
            try:
                with socket.create_connection(('127.0.0.1', state['target']['fpm_port']), timeout=.3):
                    return True
            except OSError:
                return False
        # running only means the container PID is alive. Do not trust stale
        # startup logs; wait for the restarted FPM listener before the request.
        h.wait(lambda: h.running(state['target']['fpm']) and fpm_listening(), 10, '重启后的FPM未开始监听')
        assert good(state['target'])['is_trial'];assert issued(h)['id']==state['license']['id']
    h.case(10,'FPM重启不新建试用',restart)
    def rebuild():
        # A transient tmpfs is shared by workers but disappears with the container.
        time.sleep(11)
        target=start('trial-transient',empty,transient=True);assert good(target)['is_trial']
        assert issued(h)['id']==state['license']['id']
        h.docker('stop','-t','8',target['fpm']);time.sleep(11)
        assert good(state['target'])['is_trial']
    h.case(11,'FPM临时缓存重建复用网络试用',rebuild)
    def outage():
        h.stop_api();time.sleep(1.1);bad(state['target'],'SDK_GRACE_EXPIRED');h.restore_api();assert good(state['target'])['is_trial']
    h.case(12,'FPM试用断网503、无宽限、不退出',outage)
    def expired():
        expire(h,image,state['license']);time.sleep(1.1);bad(state['target'],'LICENSE_EXPIRED')
    h.case(13,'FPM试用到期503且容器保持运行',expired)
    def formal():
        formal=h.license_new(1)
        target=start('trial-formal',formal,volume=state['target']['volume']);assert not good(target)['is_trial']
        old=issued(h);assert old['converted_at'] and old['status']=='revoked'
        assert not [r for r in h.activations(old) if r['status']=='active' and r['kind']=='floating']
    h.case(14,'FPM正式授权转正并释放试用席位',formal)
    def disabled():
        h.request('/api/v1/admin/applications/'+str(h.state['app']['id'])+'/trial',{'trial_enabled':False,'trial_days':14},'PATCH')
        target=start('trial-disabled',empty);bad(target,'TRIAL_DISABLED')
    h.case(15,'FPM关闭试用后新实例503',disabled)
