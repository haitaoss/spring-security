/*
 * Copyright 2019-2022 the original author or authors.
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

package org.springframework.gradle.github.milestones;

import org.gradle.api.Action;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;
import org.gradle.work.DisableCachingByDefault;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.springframework.gradle.github.RepositoryRef;

@DisableCachingByDefault(because = "the due date needs to be checked every time in case it changes")
public abstract class GitHubMilestoneNextVersionDueTodayTask extends DefaultTask {

	@Input
	private RepositoryRef repository = new RepositoryRef();

	@Input
	@Optional
	private String gitHubAccessToken;

	@InputFile
	public abstract RegularFileProperty getNextVersionFile();

	@OutputFile
	public abstract RegularFileProperty getIsDueTodayFile();

	private GitHubMilestoneApi milestones = new GitHubMilestoneApi();

	@TaskAction
	public void checkReleaseDueToday() throws IOException {
		File nextVersionFile = getNextVersionFile().getAsFile().get();
		Yaml yaml = new Yaml(new Constructor(NextVersionYml.class));
		NextVersionYml nextVersionYml = yaml.load(new FileInputStream(nextVersionFile));
		String nextVersion = nextVersionYml.getVersion();
		if (nextVersion == null) {
			throw new IllegalArgumentException(
					"Could not find version property in provided file " + nextVersionFile.getName());
		}
		boolean milestoneDueToday = this.milestones.isMilestoneDueToday(this.repository, nextVersion);
		Path isDueTodayPath = getIsDueTodayFile().getAsFile().get().toPath();
		/**
		 * TODOHAITAO: 2023/5/4
		 * 	直接使用 Gradle 编译、运行 是没问题的，但是想使用 IDEA 来编译运行，能指定的编译器只能是 ajc、javac、eclipse-groovy
		 * 	IDEA 指定的 ajc 是种混合模式，它是 ajc+javac 的结合，会根据文件类型决定使用 ajc 还是 javac。
		 * 	但是这个项目的编译需要 ajc + javac + groovy ，所以我取巧直接将 groovy 的语法改成 java 的语法，
		 * 	这样就能使用 IDEA 实现项目的编译和运行了
		 * */
		// Files.writeString(isDueTodayPath, String.valueOf(milestoneDueToday));
		try (FileOutputStream fileOutputStream = new FileOutputStream(isDueTodayPath.toFile());) {
			fileOutputStream.write(String.valueOf(milestoneDueToday).getBytes(StandardCharsets.UTF_8));
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		if (milestoneDueToday) {
			System.out.println("The milestone with the title " + nextVersion + " in the repository " + this.repository
					+ " is due today");
		}
		else {
			System.out.println("The milestone with the title " + nextVersion + " in the repository "
					+ this.repository + " is not due yet");
		}

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
		this.milestones = new GitHubMilestoneApi(gitHubAccessToken);
	}

}
