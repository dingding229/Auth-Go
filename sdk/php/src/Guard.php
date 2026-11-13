<?php
declare(strict_types=1);
namespace AuthGo;
const EXIT_LICENSE = 77;

/** No signals, subprocesses, shutdown hooks or implicit worker exit. */
final class Guard
{
    private array $sealed=[];
    private ?Error $failure=null;
    private bool $closed=false;
    private ?Error $closeFailure=null;
    private float $verifyAt;
    private float $heartbeatAt;
    private function __construct(private Client $client,private Result $current,private mixed $onChange=null,?array $schedule=null) {
        $this->current=$current->snapshot();
        $this->verifyAt=$schedule[0]??($client->now()+Json::num($current->data["next_check_in"]));
        $this->heartbeatAt=$schedule[1]??($client->now()+$current->heartbeatInterval);
    }
    public static function start(array $options): self {
        $config=$options["config"]??null;
        if(!is_string($config)||$config==="")throw new Error("SDK_INVALID_CONFIG","接入配置必须编译进程序");
        $key=$options["license"]??"";if($key==="")$key=getenv("AUTHGO_LICENSE")?:"";
        if($key!=="")Client::validateKey($key);
        $settings=$options["sdk_options"]??[];$settings["version"]=$options["version"]??"";
        $client=new Client($config,$settings);
        $build=function()use($client,$key,$options):self {
            $resolved=$key!==""?$key:$client->guardTrialKey();
            $cached=!isPersistentRuntime()?$client->guardCached($resolved):null;
            $guard=$cached?new self($client,$cached[0],$options["on_change"]??null,[$cached[1],$cached[2]]):new self($client,$client->check($resolved),$options["on_change"]??null);
            if($cached)$guard->tick();
            if(!isPersistentRuntime())$guard->persist();
            return $guard;
        };
        return !isPersistentRuntime()?$client->guardLocked($build):$build();
    }
    public function result(): Result {return $this->current->snapshot();}
    public function done(): bool {return $this->failure!==null;}
    public function error(): ?Error {return $this->failure;}
    private function active(): void {
        if($this->failure)throw $this->failure;
        if($this->closed)throw new Error("SDK_NOT_ACTIVATED");
    }
    public function require(string $feature=""): void {
        $this->active();$this->client->validate($this->current->ticket());
        if($feature!==""&&($this->current->features[$feature]??false)!==true)throw new Error("INVALID_POLICY");
    }
    private function changed(Result $result): void {
        $this->current=$result->snapshot();
        if($this->onChange)($this->onChange)($result->snapshot(),null);
    }
    private function persist(): void {$this->client->guardPersist($this->current,$this->verifyAt,$this->heartbeatAt);$this->current->cacheWarning=$this->client->cacheWarning;}
    public function tick(): Result {
        $this->active();
        try {
            $r=$this->current;$now=$this->client->now();$floating=(bool)($r->data["floating"]??false);
            $end=isset($r->data["expires_at"])?(float)strtotime((string)$r->data["expires_at"]):INF;
            $lease=isset($r->data["lease_expires_at"])?(float)strtotime((string)$r->data["lease_expires_at"]):INF;
            $next=min($this->verifyAt,$floating?$this->heartbeatAt:INF,$end,$r->status==="grace"?$r->usableUntil():$lease);
            if($now>=$this->verifyAt||($now>=$next&&(!$floating||$now<$this->heartbeatAt))) {
                $this->changed($this->client->verify());$this->verifyAt=$this->client->now()+Json::num($this->current->data["next_check_in"]);
            }
            if(!$this->closed&&($this->current->data["floating"]??false)&&$this->client->now()>=$this->heartbeatAt) {
                $this->changed($this->client->heartbeat());$this->heartbeatAt=$this->client->now()+$this->current->heartbeatInterval;
            }
            return $this->result();
        } catch(Error $e) {
            $this->failure=$e;$this->clearSealed();
            if($this->onChange)($this->onChange)(null,$e);
            throw $e;
        }
    }
    /** Request entry checks happen in start(); persistent apps must also schedule tick(). */
    public function sealedCheck(): void {
        try {$this->tick();$this->require();}
        catch(\Throwable $e){$this->clearSealed();throw $e;}
    }
    private function clearSealed(): void {
        foreach($this->sealed as $mount)SealedStream::remove($mount);$this->sealed=[];
    }
    public function __destruct() {$this->clearSealed();}
    /** Install the named PHP archive in memory. AUTHGO_PAYLOAD_DIR locates ciphertext only. */
    public function installSealed(string $name): void {
        $this->sealedCheck();
        if(!preg_match('/\A[a-z0-9_-]{1,128}\z/D',$name)||isset($this->sealed[$name]))throw Payload::invalid();
        $dir=getenv('AUTHGO_PAYLOAD_DIR')?:'/opt/authgo';$source=null;$key=null;$material=null;$tar=null;$files=[];
        try {
            SealedArchive::disableOpcodeCache();
            $source=SealedArchive::open($dir.'/payload.json',65536);
            $raw=stream_get_contents($source,65537);fclose($source);$source=null;
            $payload=Payload::parsePayload($raw);$entries=Json::parse(Client::decode($payload->manifest))['files'];$index=null;
            foreach($entries as $i=>$file)if($file['name']===$name){$index=$i;break;}
            if($index===null||$entries[$index]['kind']!=='php')throw Payload::invalid();
            $file=$entries[$index];$size=Payload::integer($file['size']);
            if(Payload::compare($size,(string)SealedArchive::LIMIT)>0||PHP_INT_SIZE<8)throw Payload::invalid();
            $size=(int)$size;$total=$size+16*max(1,(int)ceil($size/1048576));
            $source=SealedArchive::open($dir.'/'.$file['path'],SealedArchive::LIMIT+4096,$total);
            $material=$this->client->unlockPayloadMaterial($payload);
            $private=PayloadWatermark::read($dir,$payload,$material,$entries);
            $key=substr($material,0,32);
            $tar=SealedArchive::decrypt($source,$payload,$key,$index,$size);sodium_memzero($key);
            $files=SealedArchive::unpack($tar,true);sodium_memzero($tar);
            if($private!==null)PayloadWatermark::apply($files,$private,$index,$material);
            $this->sealedCheck();
            $this->sealed[$name]=SealedStream::install($this,$name,$files);$files=[];
        }catch(Error $e){if($e->refusal()){$this->failure=$e;$this->clearSealed();}throw $e;}
        catch(\Throwable){throw Payload::invalid();}
        finally{if($material!==null)sodium_memzero($material);if(is_resource($source))fclose($source);if($key!==null)sodium_memzero($key);if($tar!==null)sodium_memzero($tar);SealedArchive::wipe($files);}
    }
    public function close(): void {
        if(!$this->closed) {
            $this->closed=true;$this->clearSealed();
            try {$this->client->guardRelease();} catch(Error $e) {$this->closeFailure=$e;}
        }
        if($this->closeFailure)throw $this->closeFailure;
    }
}
function start_guard(array $options): Guard {return Guard::start($options);}
