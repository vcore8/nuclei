module github.com/projectdiscovery/nuclei/v2

go 1.19

require (
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible
	github.com/alecthomas/jsonschema v0.0.0-20211022214203-8b29eab41725
	github.com/andygrunwald/go-jira v1.16.0
	github.com/antchfx/htmlquery v1.3.0
	github.com/bluele/gcache v0.0.2
	github.com/corpix/uarand v0.2.0
	github.com/go-playground/validator/v10 v10.11.2
	github.com/go-rod/rod v0.112.8
	github.com/gobwas/ws v1.1.0
	github.com/google/go-github v17.0.0+incompatible
	github.com/itchyny/gojq v0.12.11
	github.com/json-iterator/go v1.1.12
	github.com/julienschmidt/httprouter v1.3.0
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/miekg/dns v1.1.53
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pkg/errors v0.9.1
	github.com/projectdiscovery/clistats v0.0.12
	github.com/projectdiscovery/fastdialer v0.0.24
	github.com/projectdiscovery/hmap v0.0.11
	github.com/projectdiscovery/interactsh v1.1.3
	github.com/projectdiscovery/rawhttp v0.1.11
	github.com/projectdiscovery/retryabledns v1.0.23
	github.com/projectdiscovery/retryablehttp-go v1.0.15
	github.com/projectdiscovery/stringsutil v0.0.2 // indirect
	github.com/projectdiscovery/yamldoc-go v1.0.4
	github.com/remeh/sizedwaitgroup v1.0.0
	github.com/rs/xid v1.5.0
	github.com/segmentio/ksuid v1.0.4
	github.com/shirou/gopsutil/v3 v3.23.3
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/cast v1.5.0
	github.com/syndtr/goleveldb v1.0.0
	github.com/valyala/fasttemplate v1.2.2
	github.com/weppos/publicsuffix-go v0.30.0
	github.com/xanzy/go-gitlab v0.82.0
	go.uber.org/multierr v1.11.0
	golang.org/x/net v0.9.0
	golang.org/x/oauth2 v0.7.0
	golang.org/x/text v0.9.0
	gopkg.in/yaml.v2 v2.4.0
	moul.io/http2curl v1.0.0
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.2.2
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.0.0
	github.com/DataDog/gostackparse v0.6.0
	github.com/Masterminds/semver/v3 v3.2.1
	github.com/Mzack9999/gcache v0.0.0-20230410081825-519e28eab057
	github.com/antchfx/xmlquery v1.3.15
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2
	github.com/aws/aws-sdk-go-v2 v1.17.8
	github.com/aws/aws-sdk-go-v2/config v1.18.20
	github.com/aws/aws-sdk-go-v2/credentials v1.13.20
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.11.61
	github.com/aws/aws-sdk-go-v2/service/s3 v1.31.2
	github.com/docker/go-units v0.5.0
	github.com/fatih/structs v1.1.0
	github.com/go-git/go-git/v5 v5.6.1
	github.com/h2non/filetype v1.1.3
	github.com/klauspost/compress v1.16.4
	github.com/labstack/echo/v4 v4.10.2
	github.com/mholt/archiver v3.1.1+incompatible
	github.com/projectdiscovery/dsl v0.0.5-0.20230328190851-15d12ab4c5e4
	github.com/projectdiscovery/fasttemplate v0.0.2
	github.com/projectdiscovery/goflags v0.1.8
	github.com/projectdiscovery/gologger v1.1.8
	github.com/projectdiscovery/httpx v1.2.9
	github.com/projectdiscovery/mapcidr v1.1.1
	github.com/projectdiscovery/nvd v1.0.10-0.20230327073015-721181aba1e8
	github.com/projectdiscovery/ratelimit v0.0.6
	github.com/projectdiscovery/rdap v0.9.1-0.20221108103045-9865884d1917
	github.com/projectdiscovery/sarif v0.0.1
	github.com/projectdiscovery/tlsx v1.0.7
	github.com/projectdiscovery/uncover v1.0.2
	github.com/projectdiscovery/utils v0.0.25
	github.com/projectdiscovery/wappalyzergo v0.0.88
	github.com/stretchr/testify v1.8.2
	gopkg.in/src-d/go-git.v4 v4.13.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	aead.dev/minisign v0.2.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.4.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.2.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v0.9.0 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.27 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.14.1 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.3.1 // indirect
	github.com/bits-and-blooms/bloom/v3 v3.3.1 // indirect
	github.com/charmbracelet/glamour v0.6.0 // indirect
	github.com/cheggaaa/pb/v3 v3.1.2 // indirect
	github.com/cloudflare/cfssl v1.6.4-0.20221208165709-c5e40da60306 // indirect
	github.com/cloudflare/circl v1.1.0 // indirect
	github.com/dlclark/regexp2 v1.8.1 // indirect
	github.com/fatih/color v1.14.1 // indirect
	github.com/google/certificate-transparency-go v1.1.4 // indirect
	github.com/google/go-github/v30 v30.1.0 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.1 // indirect
	github.com/hbakhtiyor/strsim v0.0.0-20190107154042-4d2bbb273edf // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kataras/jwt v0.1.8 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mackerelio/go-osstat v0.2.4 // indirect
	github.com/minio/selfupdate v0.6.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/muesli/termenv v0.15.1 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8 // indirect
	github.com/projectdiscovery/asnmap v1.0.3 // indirect
	github.com/projectdiscovery/cdncheck v0.0.4-0.20220413175814-b47bc2d578b1 // indirect
	github.com/projectdiscovery/freeport v0.0.4 // indirect
	github.com/shoenig/go-m1cpu v0.1.4 // indirect
	github.com/skeema/knownhosts v1.1.0 // indirect
	github.com/smartystreets/assertions v1.0.0 // indirect
	github.com/tidwall/btree v1.6.0 // indirect
	github.com/tidwall/buntdb v1.2.10 // indirect
	github.com/tidwall/gjson v1.14.4 // indirect
	github.com/tidwall/grect v0.1.4 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/rtred v0.1.2 // indirect
	github.com/tidwall/tinyqueue v0.1.1 // indirect
	github.com/yuin/goldmark v1.5.4 // indirect
	github.com/yuin/goldmark-emoji v1.0.1 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	gopkg.in/djherbis/times.v1 v1.3.0 // indirect
)

require (
	git.mills.io/prologic/smtpd v0.0.0-20210710122116-a525b76c287a // indirect
	github.com/Mzack9999/go-http-digest-auth-client v0.6.1-0.20220414142836-eb8883508809 // indirect
	github.com/Mzack9999/ldapserver v1.0.2-0.20211229000134-b44a0d6ad0dd // indirect
	github.com/PuerkitoBio/goquery v1.8.1 // indirect
	github.com/akrylysov/pogreb v0.10.1 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/antchfx/xpath v1.2.3 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/caddyserver/certmagic v0.17.2 // indirect
	github.com/cnf/structhash v0.0.0-20201127153200-e1b16c1ebc08 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/goburrow/cache v0.1.4 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/css v1.0.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.2 // indirect
	github.com/hdm/jarm-go v0.0.7 // indirect
	github.com/iancoleman/orderedmap v0.0.0-20190318233801-ac98e3ecb4b0 // indirect
	github.com/itchyny/timefmt-go v0.1.5 // indirect
	github.com/klauspost/cpuid/v2 v2.1.1 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/lor00x/goldap v0.0.0-20180618054307-a546dffdd1a3 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/mholt/acmez v1.0.4 // indirect
	github.com/microcosm-cc/bluemonday v1.0.23 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/projectdiscovery/blackrock v0.0.0-20230328171319-f24b18d05b64 // indirect
	github.com/projectdiscovery/networkpolicy v0.0.4
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/trivago/tgo v1.0.7
	github.com/ulikunitz/xz v0.5.11 // indirect
	github.com/ulule/deepcopier v0.0.0-20200430083143-45decc6639b6 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/yl2chen/cidranger v1.0.2 // indirect
	github.com/ysmood/goob v0.4.0 // indirect
	github.com/ysmood/gson v0.7.3 // indirect
	github.com/ysmood/leakless v0.8.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	github.com/zmap/rc2 v0.0.0-20190804163417-abaa70531248 // indirect
	github.com/zmap/zcrypto v0.0.0-20230205235340-d51ce4775101 // indirect
	go.etcd.io/bbolt v1.3.7 // indirect
	go.uber.org/zap v1.24.0 // indirect
	goftp.io/server/v2 v2.0.0 // indirect
	golang.org/x/crypto v0.7.0
	golang.org/x/exp v0.0.0-20230315142452-642cacee5cc0
	golang.org/x/mod v0.9.0 // indirect
	golang.org/x/sys v0.7.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.7.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.29.1 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6 // indirect
	gopkg.in/corvus-ch/zbase32.v1 v1.0.0 // indirect
)

require (
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20230217124315-7d5c6f04bbb8 // indirect
	github.com/acomagu/bufpipe v1.0.4 // indirect
	github.com/alecthomas/chroma v0.10.0
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.13.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.32 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.33 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.18.9 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-git/go-billy/v5 v5.4.1 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/labstack/gommon v0.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/nwaples/rardecode v1.1.3 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/projectdiscovery/iputil v0.0.2 // indirect
	github.com/sergi/go-diff v1.2.0 // indirect
	github.com/src-d/gcfg v1.4.0 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
)
