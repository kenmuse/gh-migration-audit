import fs from 'node:fs';
import child_process from 'node:child_process';
import path from 'node:path';
import {parseArgs} from 'node:util';
import axios from 'axios';
import tar from 'tar-stream';
import xzd from 'xz-decompress';
import unzipper from 'unzipper';
import {ReadableWebToNodeStream} from '@smessie/readable-web-to-node-stream';

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

await main();

// --------- Supporting Functions  ---------------

async function main() {
    const args = process.argv;
    const options = {
    macSign: {
        type: 'string',
        short: 'm'
    },
    winSignPfx: {
        type: 'string',
        short: 'w'
    },
    winSignPwd: {
        type: 'string',
        short: 'p'
    },
    node: {
        type: 'string',
        short: 'n'
    },
    help: {
        type: 'boolean'
    }
    };
    const { values, positionals } = parseArgs({ args, options, allowPositionals: true });
    
    if (values.help) {
        console.log('Packages the NodeJS code as a self-executing application for the specified platforms');
        console.log('Usage: node package.js [arguments] [platforms]\n');

        console.log('Platform can be macos, windows, and/or linux (default: all)')
        console.log('Options:');
        console.log('  --help:\t\tDisplays this help text');
        console.log('  --macSign:\t\tCommon name for the macOS signing certificate (default: MAC_DEVELOPER_CN)');
        console.log(`  --node:\t\tSpecific node version to use for application (default: ${version} )`);
        console.log('  --winSignPfx:\t\tPath to the PFX file containing the signing keys for Windows (default: WIN_DEVELOPER_PFX)');
        console.log('  --winSignPwd:\t\tPassword to use for signing the Windows application (default: WIN_DEVELOPER_PWD)');
    }

    if (values.macSign) {
        process.env.MAC_DEVELOPER_CN = values.macSign;
    }

    if (values.winSignPfx) {
        process.env.WIN_DEVELOPER_PFX = values.winSignPfx;
    }

    if (values.winSignPwd) {
        process.env.WIN_DEVELOPER_PWD = values.winSignPwd;
    }

    // If user specifies platforms, they must be in the list of all available platforms
    const platformPositionals = positionals.slice(2);
    const buildPlatforms = platformPositionals && platformPositionals.length > 0 
                           ? platformPositionals
                                .flatMap(t => t.split(','))
                                .map(t => t.toLowerCase())
                                .map(t => t === 'macos' || t === 'mac' ? 'darwin' : t === 'windows' ? 'win' : t)
                                .filter(t => platforms.includes(t))
                             : platforms;
    await createSingleExecutableApplication(values.node ?? version, buildPlatforms, archs);
}


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

    // Web stream to decompress XZ files
    const xzDecompressStream = new xzd.XzReadableStream(inputStream);

    // Convert to Node stream to pipe to the TAR extractor
    new ReadableWebToNodeStream(xzDecompressStream)
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

async function downloadNodePlatformBinary(platform, arch, nodeVersion, outputFolder) {
    const compressedExtension = platform == 'win' ? 'zip' : 'tar.xz';
    const binaryExtension = platform == 'win' ? '.exe' : '';
    const outputPath = path.resolve(path.join(outputFolder, `migration-audit-${platform}-${arch}${binaryExtension}`));
    const url = `https://nodejs.org/dist/v${nodeVersion}/node-v${nodeVersion}-${platform}-${arch}.${compressedExtension}`;
    console.log(`Retrieving ${url}`);

    const response = await axios({
        method: 'GET',
        url: url,
        responseType: 'stream',
        adapter: 'fetch'
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

async function createSingleExecutableApplication(nodeVersion, platforms, archs) {
    const binaryOutputFolder = prepareOutputDirectory();

    exec('node', ['build.js']);
    exec('node', ['--experimental-sea-config', 'sea-config.json']);

    for (const platform of platforms) {
        for (const arch of archs) {
            const nodeBinaryPath = await downloadNodePlatformBinary(platform, arch, nodeVersion, binaryOutputFolder);
            packageAsSingleExecutableApplication(binaryOutputFolder, nodeBinaryPath, platform, arch);
        }
    }
}