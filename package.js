import fs from 'node:fs';
import child_process from 'node:child_process';
import path from 'node:path';
import axios from 'axios';
import tar from 'tar-stream';
import xz from 'xz';
import unzipper from 'unzipper';

const version = '20.17.0';
const platforms = [
    'darwin',
    'linux',
    'win'
];

const archs = [
    'arm64',
    'x64'
];

// Automatically signs files if MAC_DEVELOPER_CN 
// or WIN_DEVELOPER_PFX and WIN_DEVELOPER_PWD are present
await createSingleExecutableApplication(platforms, archs);

// --------- Supporting Functions  ---------------

async function uncompressZip(inputStream, outputStream) {
    //const stream = inputStream.pipe(zlib.createUnzip()).pipe(outputFile)
    //await new Promise(resolve => stream.on('finish', resolve))
    const zip = inputStream.pipe(unzipper.Parse({forceStream: true}));
    for await (const entry of zip) {
      const fileName = entry.path;
      const type = entry.type;
      if (type ==='File' && fileName.endsWith('/node.exe')) {
        await new Promise((resolve, reject) =>
        {
            console.debug(`Extracting ${fileName}`);
            entry.pipe(outputStream)
            .on('finish', () => {
                console.debug(`Extraction complete`);
                resolve()
            })
            .on('error', (err) => { 
                console.debug(`Extraction failed: ${err}`);
                reject(err);
            });
        });
      } else {
        entry.autodrain();
      }
    }
}

async function uncompress(inputStream, outputStream) {
    // Extract the node binary
    const extract = tar.extract();
    const chunks = [];

    extract.on('entry', function (header, stream, next) {
        if (header.name.endsWith('/bin/node')) {
            console.debug(`Extracting ${header.name}`);
            stream.on('data', function (chunk) {
                chunks.push(chunk);
            });
        }

        stream.on('end', function () {
            next();
        });

        stream.resume();
    });

    extract.on('finish', function () {
        if (chunks.length) {
            var data = Buffer.concat(chunks);
            outputStream.write(data);
            console.debug(`Extraction complete`);
        }
    })

    inputStream
        .pipe(new xz.Decompressor())
        .pipe(extract);
    
    await new Promise(resolve => extract.on('finish', resolve));
}

function exec(cmd, args){
    const processResult = child_process.spawnSync(
        cmd,
        args,
        {
            encoding: 'utf8',
            shell: true,
        }
    );
    console.log(processResult.stdout);
    if (processResult.stderr){
        console.error(processResult.stderr);
    }
}

function writeSignature(platform, arch, outputPath) {
    if (platform == 'darwin' && arch == 'arm64') {
        if (process.env.MAC_DEVELOPER_CN) {
            exec('codesign', ['--sign', process.env.MAC_DEVELOPER_CN, outputPath]);
        }
    }
    else if (platform  == 'win') {
        // Not required
        if (process.env.WIN_DEVELOPER_PFX && process.env.WIN_DEVELOPER_PWD) {
            exec('signtool', ['sign',
                '/fd', 'SHA256',
                '/f', process.env.WIN_DEVELOPER_PFX, '/p', process.env.WIN_DEVELOPER_PWD,
                '/t', 'http://timestamp.digicert.com',
                nodeBinaryPath]);
        }
    }
}

function prepareSignature(platform, arch, nodeBinaryPath) {
    if (platform == 'darwin' && arch == 'arm64') {
        exec('xattr', ['-cr', nodeBinaryPath]);
        exec('codesign', ['--remove-signature', nodeBinaryPath]);
        return ['--macho-segment-name', 'NODE_SEA'];
    }
    else if (platform  == 'win') {
        exec('signtool', ['remove', '/s', nodeBinaryPath]);
    }
    return [];
}

function prepareOutputDirectory() {
    const binFolder = path.resolve('./bin');
    if (fs.existsSync(binFolder)) {
        fs.rmSync(binFolder, { recursive: true });
    }
    fs.mkdirSync(binFolder, { recursive: true });
    return binFolder;
}

function packageAsSingleExecutableApplication(binaryOutputFolder, nodeBinaryPath, platform, arch) {
    console.debug('Writing executable');
    let params = ['postject', nodeBinaryPath, 'NODE_SEA_BLOB', path.resolve(path.join(binaryOutputFolder, 'migration-audit.blob')), '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'];

    params.concat(prepareSignature(platform, arch, nodeBinaryPath));

    // Linux will have a few warnings: https://github.com/nodejs/postject/issues/83
    exec('npx', params);

    writeSignature(platform, arch, nodeBinaryPath);
}

async function downloadNodePlatformBinary(platform, arch, outputFolder) {
    const compressedExtension = platform == 'win' ? 'zip' : 'tar.xz';
    const binaryExtension = platform == 'win' ? '.exe' : '';
    const outputPath = path.resolve(path.join(outputFolder, `migration-audit-${platform}-${arch}${binaryExtension}`));
    const url = `https://nodejs.org/dist/v${version}/node-v${version}-${platform}-${arch}.${compressedExtension}`;
    console.log(`Retrieving ${url}`);

    const response = await axios({
        method: 'GET',
        url: url,
        responseType: 'stream'
    });

    // pipe the result stream into a file on disc
    const stream = fs.createWriteStream(outputPath);
    console.debug('Processing compressed stream');
    //response.data.pipe(stream);
    //stream.close();
    if (platform == 'win') {
        await uncompressZip(response.data, stream);
    }
    else {
        await uncompress(response.data, stream);
    }

    stream.close();
    return outputPath;
}

async function createSingleExecutableApplication(platforms, archs) {
    const binaryOutputFolder = prepareOutputDirectory();

    exec('node', ['build.js']);
    exec('node', ['--experimental-sea-config', 'sea-config.json']);

    for (const platform of platforms) {
        for (const arch of archs) {
            const nodeBinaryPath = await downloadNodePlatformBinary(platform, arch, binaryOutputFolder);
            packageAsSingleExecutableApplication(binaryOutputFolder, nodeBinaryPath, platform, arch);
        }
    }
}