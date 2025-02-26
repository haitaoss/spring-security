/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.gradle.github.release;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Collectors;

import org.gradle.api.Action;
import org.gradle.api.DefaultTask;
import org.gradle.api.Project;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.TaskAction;

import org.springframework.gradle.github.RepositoryRef;
import org.springframework.gradle.github.changelog.GitHubChangelogPlugin;

/**
 * @author Steve Riesenberg
 */
public class CreateGitHubReleaseTask extends DefaultTask {
	@Input
	private RepositoryRef repository = new RepositoryRef();

	@Input @Optional
	private String gitHubAccessToken;

	@Input
	private String version;

	@Input @Optional
	private String branch = "main";

	@Input
	private boolean createRelease = false;

	@TaskAction
	public void createGitHubRelease() {
		String body = readReleaseNotes();
		Release release = Release.tag(this.version)
				.commit(this.branch)
				.name(this.version)
				.body(body)
				.preRelease(this.version.contains("-"))
				.build();

		System.out.printf("%sCreating GitHub release for %s/%s@%s\n",
				this.createRelease ? "" : "[DRY RUN] ",
				this.repository.getOwner(),
				this.repository.getName(),
				this.version
		);
		System.out.printf("  Release Notes:\n\n----\n%s\n----\n\n", body.trim());

		if (this.createRelease) {
			GitHubReleaseApi github = new GitHubReleaseApi(this.gitHubAccessToken);
			github.publishRelease(this.repository, release);
		}
	}

	private String readReleaseNotes() {
		Project project = getProject();
		File inputFile = project.file(Paths.get(project.getBuildDir().getPath(), GitHubChangelogPlugin.RELEASE_NOTES_PATH));
		/**
		 * TODOHAITAO: 2023/5/4
		 * 	直接使用 Gradle 编译、运行 是没问题的，但是想使用 IDEA 来编译运行，能指定的编译器只能是 ajc、javac、eclipse-groovy
		 * 	IDEA 指定的 ajc 是种混合模式，它是 ajc+javac 的结合，会根据文件类型决定使用 ajc 还是 javac。
		 * 	但是这个项目的编译需要 ajc + javac + groovy ，所以我取巧直接将 groovy 的语法改成 java 的语法，
		 * 	这样就能使用 IDEA 实现项目的编译和运行了
		 */
		/*try {
			return Files.readString(inputFile.toPath());
		} catch (IOException ex) {
			throw new RuntimeException("Unable to read release notes from " + inputFile, ex);
		}*/
		String note = null;
		try (FileReader in = new FileReader(inputFile);
			 BufferedReader bufferedReader = new BufferedReader(in)) {
			note = bufferedReader.lines().collect(Collectors.joining(""));
		}
		catch (IOException ex) {
			throw new RuntimeException("Unable to read release notes from " + inputFile, ex);
		}

		return note;
	}

	public RepositoryRef getRepository() {
		return repository;
	}

	public void repository(Action<RepositoryRef> repository) {
		repository.execute(this.repository);
	}

	public void setRepository(RepositoryRef repository) {
		this.repository = repository;
	}

	public String getGitHubAccessToken() {
		return gitHubAccessToken;
	}

	public void setGitHubAccessToken(String gitHubAccessToken) {
		this.gitHubAccessToken = gitHubAccessToken;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getBranch() {
		return branch;
	}

	public void setBranch(String branch) {
		this.branch = branch;
	}

	public boolean isCreateRelease() {
		return createRelease;
	}

	public void setCreateRelease(boolean createRelease) {
		this.createRelease = createRelease;
	}
}
